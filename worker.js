
import { httpServerHandler } from "cloudflare:node";
import app from "./server.js";

// Start the existing Express application on the
// internal port used by Cloudflare's HTTP server adapter.
app.listen(3000);

export default httpServerHandler({ port: 3000 });
