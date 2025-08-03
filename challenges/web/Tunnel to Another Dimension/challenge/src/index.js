import express from "express";
import vm from "node:vm";
import pug from "pug";
import path from "path";
import { fileURLToPath } from "url";

const app = express();

const PORT = Number(process.env.PORT) || 8000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.set("view engine", "html");
app.set("views", "views");

app.get("/", (req, res) => {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  const filePath = path.join(__dirname, "views", "index.html");

  res.sendFile(filePath);
});

app.post("/render", (req, res) => {
  try {
    const template = req.body.template;
    if (!template) {
      return res.status(400).send("Template is required");
    }

    if (typeof template !== "string") {
      return res.status(400).send("Template must be a string");
    }

    const script = new vm.Script(`
    const rendered = render(template);
    result = rendered;
    `); // sandboxed template , fully secure

    const context = vm.createContext({
      render: (tmpl) => pug.render(tmpl),
      template,
      result: "",
    }); //limited context

    script.runInContext(context); //run in isolated context
    res.status(200).send(context.result);
  } catch (error) {
    console.error("Error rendering template:", error);
    res.status(500).send(`Error rendering template`);
  }
});

process.on("uncaughtException", (err) => {
  console.error("Uncaught Exception:", err);
});

process.on("unhandledRejection", (reason, promise) => {
  console.error("Unhandled Rejection at:", promise, "reason:", reason);
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
