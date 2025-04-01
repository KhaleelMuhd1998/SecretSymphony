import time
from datetime import datetime

# Get the current timestamp in seconds
timestamp = time.time()
print(f"Current Timestamp (in seconds): {timestamp}")

# Convert the timestamp to a readable date and time
readable_date = datetime.fromtimestamp(timestamp)
print(f"Readable Date and Time: {readable_date}")

# Extract specific components from the timestamp
year = readable_date.year
month = readable_date.month
day = readable_date.day
hour = readable_date.hour
minute = readable_date.minute
second = readable_date.second

print(f"Year: {year}, Month: {month}, Day: {day}")
print(f"Time: {hour}:{minute}:{second}")