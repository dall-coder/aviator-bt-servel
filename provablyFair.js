const crypto = require('crypto');

function makeServerSeed() {
  return crypto.randomBytes(32).toString('hex');
}

function commitServerSeed(serverSeed) {
  return crypto.createHash('sha256').update(serverSeed).digest('hex');
}

// Calcula um número U em (0,1) a partir do HMAC_SHA256(serverSeed, roundId)
function hmacToUniform(serverSeed, roundId) {
  const hmac = crypto.createHmac('sha256', serverSeed).update(String(roundId)).digest('hex');
  const num = BigInt('0x' + hmac);
  const denom = BigInt(1) << BigInt(256);
  // Reduce precision to fit into JS Number safely
  const scaled = Number((num * BigInt(1e12)) / denom) / 1e12;
  return Math.min(Math.max(scaled, Number.EPSILON), 1 - Number.EPSILON);
}

function computeCrashMultiplierFromU(u, maxMultiplier = 500) {
  // example: heavy-tail using 1/(1-u)
  const raw = 1 / (1 - u);
  const capped = Math.min(raw, maxMultiplier);
  return Math.floor(capped * 100) / 100;
}

function getCrashMultiplier(serverSeed, roundId, maxMultiplier = 500) {
  const u = hmacToUniform(serverSeed, roundId);
  return computeCrashMultiplierFromU(u, maxMultiplier);
}

module.exports = {
  makeServerSeed,
  commitServerSeed,
  getCrashMultiplier,
  hmacToUniform,
  computeCrashMultiplierFromU,
};