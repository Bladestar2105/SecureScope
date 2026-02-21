const ExploitDbSyncService = require('./services/exploitDbSyncService');
const { performance } = require('perf_hooks');

async function runBenchmark() {
    console.log('Starting benchmark for getRepoStats...');
    const start = performance.now();
    const stats = ExploitDbSyncService.getRepoStats();
    const end = performance.now();
    console.log('Stats:', stats);
    console.log(`Execution time: ${(end - start).toFixed(2)}ms`);
}

runBenchmark().catch(console.error);
