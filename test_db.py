from sqlalchemy import create_engine

# Replace with your connection string
DATABASE_URL=mssql+pyodbc://AfrikaESGIndex:Sgb3%401017@afrikaesgindex.database.windows.net/AfrikaESGIndex?driver=ODBC+Driver+18+for+SQL+Server&authentication=ActiveDirectoryPassword

engine = create_engine(DATABASE_URL, echo=True, connect_args={'timeout': 30})

try:
    with engine.connect() as conn:
        result = conn.execute("SELECT 1")
        print("Connection successful:", result.fetchone())
except Exception as e:
    print("Connection failed:", e)
