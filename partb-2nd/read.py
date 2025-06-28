import pandas as pd

# Define the path to the raw dataset
file_path = 'C:/Users/abhis/Desktop/SSH-Shell-Attacks-main/data/raw/ssh_attacks.parquet'

try:
    # Read the Parquet file into a pandas DataFrame
    df = pd.read_parquet(file_path)

    # Display the first 5 rows to see its structure
    print("Successfully loaded the dataset. Here are the first 5 rows:")
    print(df.head())

    # Display information about the columns and data types
    print("\nDataset Info:")
    df.info()

except FileNotFoundError:
    print(f"Error: The file was not found at {file_path}")
except Exception as e:
    print(f"An error occurred: {e}")
