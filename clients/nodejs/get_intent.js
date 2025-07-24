import axios from 'axios';

const RPC_SERVER = 'http://localhost:8082';

// Function to get an intent by hash
async function getIntentByHash(hash) {
    try {
        console.log('🔍 Fetching intent by hash...');
        console.log('Intent hash:', hash);

        const response = await axios.get(`${RPC_SERVER}/intent/${hash}`);

        console.log('✅ Intent fetched successfully!');
        console.log('Intent data:', JSON.stringify(response.data, null, 2));
        return response.data;
    } catch (error) {
        console.error('❌ Failed to fetch intent:', error.message);
        if (error.response) {
            console.error('Response status:', error.response.status);
            console.error('Response data:', error.response.data);
            
            if (error.response.status === 404) {
                console.error('💡 Intent not found. Make sure the hash is correct.');
            }
        }
        throw error;
    }
}

// Function to list all intents
async function listAllIntents() {
    try {
        console.log('📋 Fetching all intents...');

        const response = await axios.get(`${RPC_SERVER}/intents`);

        console.log('✅ Intents fetched successfully!');
        console.log(`Found ${response.data.count} intents:`);
        console.log('');
        
        if (response.data.intents && response.data.intents.length > 0) {
            response.data.intents.forEach((intentWithStatus, index) => {
                console.log(`--- Intent ${index + 1} ---`);
                console.log('Hash:', intentWithStatus.hash);
                console.log('Status:', intentWithStatus.status);
                console.log('Solver:', intentWithStatus.solver);
                console.log('Source Chain:', intentWithStatus.intent.source_chain);
                console.log('Target Chain:', intentWithStatus.intent.target_chain);
                console.log('Amount:', intentWithStatus.intent.amount);
                console.log('Source Token:', intentWithStatus.intent.source_token);
                console.log('Target Token:', intentWithStatus.intent.target_token);
                console.log('Source Address:', intentWithStatus.intent.source_address);
                console.log('Target Address:', intentWithStatus.intent.target_address);
                console.log('');
            });
        } else {
            console.log('No intents found.');
        }
        
        return response.data;
    } catch (error) {
        console.error('❌ Failed to fetch intents:', error.message);
        if (error.response) {
            console.error('Response status:', error.response.status);
            console.error('Response data:', error.response.data);
        }
        throw error;
    }
}

// Function to get intent status by hash (simplified version)
async function getIntentStatus(hash) {
    try {
        const intent = await getIntentByHash(hash);
        return intent.status;
    } catch (error) {
        console.error('❌ Failed to get intent status');
        throw error;
    }
}

// Function to get intent solver by hash (simplified version)
async function getIntentSolver(hash) {
    try {
        const intent = await getIntentByHash(hash);
        return intent.solver;
    } catch (error) {
        console.error('❌ Failed to get intent solver');
        throw error;
    }
}

// Function to search intents by criteria
async function searchIntents(criteria = {}) {
    try {
        const allIntents = await listAllIntents();
        
        if (!criteria || Object.keys(criteria).length === 0) {
            return allIntents;
        }

        const filteredIntents = allIntents.intents.filter(intentWithStatus => {
            const intent = intentWithStatus.intent;
            
            if (criteria.source_chain && intent.source_chain !== criteria.source_chain) {
                return false;
            }
            if (criteria.target_chain && intent.target_chain !== criteria.target_chain) {
                return false;
            }
            if (criteria.status && intentWithStatus.status !== criteria.status) {
                return false;
            }
            if (criteria.source_token && intent.source_token !== criteria.source_token) {
                return false;
            }
            if (criteria.target_token && intent.target_token !== criteria.target_token) {
                return false;
            }
            
            return true;
        });

        console.log(`🔍 Found ${filteredIntents.length} intents matching criteria`);
        return {
            intents: filteredIntents,
            count: filteredIntents.length
        };
    } catch (error) {
        console.error('❌ Failed to search intents');
        throw error;
    }
}

// Main function
async function main() {
    const args = process.argv.slice(2);
    const command = args[0] || 'list';
    const parameter = args[1];

    console.log('🚀 Intent Query Tool');
    console.log('===================');
    console.log(`RPC Server: ${RPC_SERVER}`);
    console.log(`Command: ${command}`);
    console.log('');

    try {
        switch (command) {
            case 'get':
            case 'fetch':
                if (!parameter) {
                    console.error('❌ Hash parameter required for get command');
                    console.log('Usage: node get_intent.js get <hash>');
                    process.exit(1);
                }
                await getIntentByHash(parameter);
                break;

            case 'list':
            case 'all':
                await listAllIntents();
                break;

            case 'status':
                if (!parameter) {
                    console.error('❌ Hash parameter required for status command');
                    console.log('Usage: node get_intent.js status <hash>');
                    process.exit(1);
                }
                const status = await getIntentStatus(parameter);
                console.log(`📊 Intent status: ${status}`);
                break;

            case 'solver':
                if (!parameter) {
                    console.error('❌ Hash parameter required for solver command');
                    console.log('Usage: node get_intent.js solver <hash>');
                    process.exit(1);
                }
                const solver = await getIntentSolver(parameter);
                console.log(`🔧 Intent solver: ${solver}`);
                break;

            case 'search':
                // Example search by source chain
                const searchCriteria = parameter ? { source_chain: parameter } : {};
                await searchIntents(searchCriteria);
                break;

            case 'help':
                console.log('Available commands:');
                console.log('  list           - List all intents');
                console.log('  get <hash>     - Get intent by hash');
                console.log('  status <hash>  - Get intent status by hash');
                console.log('  solver <hash>  - Get intent solver by hash');
                console.log('  search [chain] - Search intents (optionally by source chain)');
                console.log('  help           - Show this help');
                console.log('');
                console.log('Examples:');
                console.log('  node get_intent.js list');
                console.log('  node get_intent.js get 0x1234abcd...');
                console.log('  node get_intent.js status 0x1234abcd...');
                console.log('  node get_intent.js solver 0x1234abcd...');
                console.log('  node get_intent.js search ethereum');
                break;

            default:
                console.error(`❌ Unknown command: ${command}`);
                console.log('Available commands: list, get, status, solver, search, help');
                process.exit(1);
        }
    } catch (error) {
        console.error('❌ Operation failed');
        process.exit(1);
    }
}

// Export functions for use in other modules
export { getIntentByHash, listAllIntents, getIntentStatus, getIntentSolver, searchIntents };

// Run if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
    main();
} 