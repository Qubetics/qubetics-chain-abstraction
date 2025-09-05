import rocksdb from 'rocksdb';

// open the database in read-only mode
const db = rocksdb('../../data/rocksdb-12D3KooW');

db.open({ 
    createIfMissing: false,
    readOnly: true,
    errorIfExists: false
}, (err) => {
    if (err) {
        console.error('Error opening database:', err);
        return;
    }

    console.log('Database opened successfully in read-only mode');
    
    // create an iterator
    const iterator = db.iterator();

    function next() {
        iterator.next((err, key, value) => {
            if (err) {
                console.error('Error iterating:', err);
                iterator.end(() => db.close(() => console.log('DB closed')));
                return;
            }

            if (key && value) {
                console.log('Key:', key.toString(), 'Value:', value.toString());
                next(); // keep iterating
            } else {
                iterator.end(() => db.close(() => console.log('DB closed')));
            }
        });
    }

    next();
});