// Get the current timestamp
const timestamp = Date.now();
console.log(`Current Timestamp: ${timestamp}`);

// Convert the timestamp to a readable date
const readableDate = new Date(timestamp);
console.log(`Readable Date: ${readableDate}`);

// Extract specific components from the timestamp
const year = readableDate.getFullYear();
const month = readableDate.getMonth() + 1; // Months are zero-based
const day = readableDate.getDate();
const hours = readableDate.getHours();
const minutes = readableDate.getMinutes();
const seconds = readableDate.getSeconds();

console.log(`Year: ${year}, Month: ${month}, Day: ${day}`);
console.log(`Time: ${hours}:${minutes}:${seconds}`);