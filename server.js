const express = require("express");
const cors = require("cors");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;

// Admin credentials
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "Gopal";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "941193";

// Secret for login tokens
const SECRET =
    process.env.AUTH_SECRET || "change-this-secret-123456";

const DATA_DIR = path.join(__dirname, "resources");

if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

app.use(cors({
    origin: true,
    credentials: true
}));

app.use(express.json());

const upload = multer({
    dest: DATA_DIR,
    limits: {
        fileSize: 20 * 1024 * 1024
    },
    fileFilter: (req, file, cb) => {

        const ext =
            path.extname(file.originalname).toLowerCase();

        if (ext !== ".pdf") {
            return cb(
                new Error("Only PDF files are allowed.")
            );
        }

        cb(null, true);
    }
});


/* -------------------------
   TOKEN SYSTEM
------------------------- */

function createToken(username) {

    const data =
        `${username}:${Date.now()}`;

    const signature =
        crypto
            .createHmac("sha256", SECRET)
            .update(data)
            .digest("hex");

    return Buffer
        .from(`${data}:${signature}`)
        .toString("base64url");
}


function verifyToken(token) {

    try {

        if (!token) {
            return false;
        }

        const decoded =
            Buffer
                .from(token, "base64url")
                .toString();

        const parts =
            decoded.split(":");

        if (parts.length !== 3) {
            return false;
        }

        const username = parts[0];
        const time = Number(parts[1]);
        const signature = parts[2];

        if (username !== ADMIN_USERNAME) {
            return false;
        }

        // Login valid for 24 hours
        if (
            Date.now() - time >
            24 * 60 * 60 * 1000
        ) {
            return false;
        }

        const data =
            `${username}:${time}`;

        const expected =
            crypto
                .createHmac("sha256", SECRET)
                .update(data)
                .digest("hex");

        return crypto.timingSafeEqual(
            Buffer.from(signature),
            Buffer.from(expected)
        );

    } catch {
        return false;
    }
}


function adminOnly(req, res, next) {

    const auth =
        req.headers.authorization || "";

    const token =
        auth.startsWith("Bearer ")
            ? auth.substring(7)
            : "";

    if (!verifyToken(token)) {

        return res.status(401).json({
            error: "Admin login required."
        });

    }

    next();
}


/* -------------------------
   HOME
------------------------- */

app.get("/", (req, res) => {

    res.json({
        ok: true,
        service: "Gopal Resources API"
    });

});


/* -------------------------
   ADMIN LOGIN
------------------------- */

app.post("/api/admin/login", (req, res) => {

    const username =
        String(req.body.username || "");

    const password =
        String(req.body.password || "");

    if (
        username !== ADMIN_USERNAME ||
        password !== ADMIN_PASSWORD
    ) {

        return res.status(401).json({
            success: false,
            error: "Invalid username or password."
        });

    }

    const token =
        createToken(username);

    res.json({
        success: true,
        token
    });

});


/* -------------------------
   CHECK LOGIN
------------------------- */

app.get(
    "/api/admin/check",
    adminOnly,
    (req, res) => {

        res.json({
            loggedIn: true
        });

    }
);


/* -------------------------
   PUBLIC RESOURCE LIST
------------------------- */

app.get(
    "/api/resources",
    (req, res) => {

        const files =
            fs.readdirSync(DATA_DIR);

        const resources =
            files
                .filter(file =>
                    file.endsWith(".json")
                )
                .map(file => {

                    try {

                        const data =
                            JSON.parse(
                                fs.readFileSync(
                                    path.join(
                                        DATA_DIR,
                                        file
                                    ),
                                    "utf8"
                                )
                            );

                        return data;

                    } catch {

                        return null;

                    }

                })
                .filter(Boolean);

        res.json(resources);

    }
);


/* -------------------------
   ADMIN RESOURCE LIST
------------------------- */

app.get(
    "/api/admin/resources",
    adminOnly,
    (req, res) => {

        const files =
            fs.readdirSync(DATA_DIR);

        const resources =
            files
                .filter(file =>
                    file.endsWith(".json")
                )
                .map(file => {

                    try {

                        return JSON.parse(
                            fs.readFileSync(
                                path.join(
                                    DATA_DIR,
                                    file
                                ),
                                "utf8"
                            )
                        );

                    } catch {

                        return null;

                    }

                })
                .filter(Boolean);

        res.json(resources);

    }
);


/* -------------------------
   UPLOAD PDF
------------------------- */

app.post(
    "/api/admin/upload",
    adminOnly,
    upload.single("pdf"),
    (req, res) => {

        try {

            if (!req.file) {

                return res.status(400).json({
                    error: "Please select a PDF."
                });

            }

            const name =
                String(
                    req.body.name || ""
                )
                .trim()
                .slice(0, 150);

            const subject =
                String(
                    req.body.subject || "Other"
                )
                .trim()
                .slice(0, 80);

            if (!name) {

                fs.unlinkSync(req.file.path);

                return res.status(400).json({
                    error: "Resource name is required."
                });

            }

            const id =
                crypto
                    .randomBytes(12)
                    .toString("hex");

            const pdfName =
                `${id}.pdf`;

            const finalPath =
                path.join(
                    DATA_DIR,
                    pdfName
                );

            fs.renameSync(
                req.file.path,
                finalPath
            );

            const resource = {

                id,

                name,

                subject,

                file:
                    `/api/resources/${id}`,

                createdAt:
                    new Date().toISOString()

            };

            fs.writeFileSync(
                path.join(
                    DATA_DIR,
                    `${id}.json`
                ),
                JSON.stringify(
                    resource,
                    null,
                    2
                )
            );

            res.json({
                success: true,
                resource
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                error: "Upload failed."
            });

        }

    }
);


/* -------------------------
   OPEN PDF
------------------------- */

app.get(
    "/api/resources/:id",
    (req, res) => {

        const id =
            req.params.id;

        if (
            !/^[a-f0-9]+$/i.test(id)
        ) {

            return res.status(400).end();

        }

        const file =
            path.join(
                DATA_DIR,
                `${id}.pdf`
            );

        if (!fs.existsSync(file)) {

            return res.status(404).send(
                "Resource not found."
            );

        }

        res.setHeader(
            "Content-Type",
            "application/pdf"
        );

        // Browser mein open hoga,
        // public page par Download button nahi hoga.
        res.setHeader(
            "Content-Disposition",
            "inline"
        );

        res.sendFile(file);

    }
);


/* -------------------------
   DELETE RESOURCE
------------------------- */

app.delete(
    "/api/admin/resources/:id",
    adminOnly,
    (req, res) => {

        const id =
            req.params.id;

        if (
            !/^[a-f0-9]+$/i.test(id)
        ) {

            return res.status(400).json({
                error: "Invalid resource."
            });

        }

        const pdf =
            path.join(
                DATA_DIR,
                `${id}.pdf`
            );

        const json =
            path.join(
                DATA_DIR,
                `${id}.json`
            );

        if (fs.existsSync(pdf)) {
            fs.unlinkSync(pdf);
        }

        if (fs.existsSync(json)) {
            fs.unlinkSync(json);
        }

        res.json({
            success: true
        });

    }
);


/* -------------------------
   ERROR HANDLER
------------------------- */

app.use(
    (error, req, res, next) => {

        console.error(error);

        res.status(400).json({
            error:
                error.message ||
                "Something went wrong."
        });

    }
);


/* -------------------------
   START SERVER
------------------------- */

app.listen(
    PORT,
    () => {

        console.log(
            `Gopal Resources API running on port ${PORT}`
        );

    }
);
