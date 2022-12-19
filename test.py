import pandas as pd

df = pd.read_csv('Lab_project/majestic_million.csv')
df = df[df['TLD'] == 'sg']
df = df[['Domain', 'TLD']][:1000]

df.to_csv('Lab_project/sg_websites.csv', index=False)
