// Runs only when MongoDB initializes a fresh data volume.
const verifier = db.getSiblingDB("siros_verifier");
verifier.createUser({
  user: "verifier-user",
  pwd: process.env.MONGODB_APP_PASSWORD,
  roles: [{ role: "readWrite", db: "siros_verifier" }],
});
