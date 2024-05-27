# Not sure how this will act on a number of machines.

import pandas as pd

df = pd.read_csv('results.csv')

df = df.drop_duplicates()

df = df.sort_values(by=['Worker ID', 'IP Address'])

# Group by Worker ID, IP Address, Log File, and Error Type
df['Error Count'] = 1
df_grouped = df.groupby(['Worker ID', 'IP Address', 'Log File', 'Error Type'], as_index=False).agg({
    'Error Message': 'first',
    'Error Count': 'sum'
})

df_grouped.to_csv('cleaned_results_grouped.csv', index=False)

print(df_grouped)
