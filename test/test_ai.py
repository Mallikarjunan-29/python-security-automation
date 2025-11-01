from google import genai
from dotenv import load_dotenv
load_dotenv()
import os
client = genai.Client(api_key=os.getenv("GEMINIKEY"))
response= client.models.generate_content(
    model="gemini-2.5-flash",contents="What is brute force in CyberSecurity"
)
print(response.text)
