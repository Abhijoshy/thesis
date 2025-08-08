@echo off
echo.
echo ====================================================
echo    GitHub Secrets Setup Helper
echo ====================================================
echo.

if exist "ec2keypair.pem" (
    echo Found ec2keypair.pem file
    echo.
    echo COPY THE FOLLOWING CONTENT FOR EC2_SSH_KEY SECRET:
    echo ====================================================
    type ec2keypair.pem
    echo ====================================================
    echo.
) else (
    echo ERROR: ec2keypair.pem file not found!
    pause
    exit /b 1
)

echo.
echo GitHub Secrets to add:
echo ====================================================
echo Secret Name: EC2_SSH_KEY
echo Secret Value: [The content above - copy everything]
echo.
echo Secret Name: EC2_HOST  
echo Secret Value: 16.16.25.121
echo ====================================================
echo.

echo Steps:
echo 1. Go to: https://github.com/Abhijoshy/thesis/settings/secrets/actions
echo 2. Click: New repository secret
echo 3. Add EC2_SSH_KEY with the private key content above
echo 4. Add EC2_HOST with value: 16.16.25.121
echo.
pause
