user={
    "username":"admin",
    "password":"pass123"
}

def maskpassword(pwd):    
    passwordlength=len(pwd)
    if passwordlength>2:
        star='*' * (passwordlength-2)
        maskedpassword = f"{pwd[0]}{star}{pwd[-1]}"
    elif passwordlength==2:
        star='*' * (passwordlength-1)
        maskedpassword = f"{pwd[0]}{star}{pwd[-1]}"
    elif passwordlength==1:
        maskedpassword = "*"
    else:
        maskedpassword=""        
    return maskedpassword

if user:
    password = user.get("password","")
    mask= maskpassword(password)

print(f"user {user['username']}'s password is {mask}")

