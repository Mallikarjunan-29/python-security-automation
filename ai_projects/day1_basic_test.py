from google import genai
import os

gemini_key=os.getenv('GEMINIKEY')
client=genai.Client(api_key=gemini_key)
response=client.models.generate_content(
    model="gemini-2.0-flash",contents="Explain about brute force in 100 words or less"
)
print(response.text)