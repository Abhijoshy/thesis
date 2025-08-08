@echo off
echo ====================================================
echo    AWS Infrastructure Setup for Abhishek's Project
echo ====================================================
echo.
echo This script will create:
echo - VPC with CIDR 10.0.0.0/16
echo - Public Subnet with CIDR 10.0.1.0/24
echo - Internet Gateway
echo - Route Table with Internet Access
echo - Security Group (SSH, Flask App, HTTP/HTTPS)
echo - EC2 Instance (t3.micro with Amazon Linux 2023)
echo.
pause

REM Set variables
set PREFIX=abhishek
set VPC_CIDR=10.0.0.0/16
set SUBNET_CIDR=10.0.1.0/24
set REGION=eu-north-1
set AZ=eu-north-1a
set AMI_ID=ami-09d840fad48a1395e
set INSTANCE_TYPE=t3.micro
set KEY_PAIR=ec2keypair

echo.
echo ====================================================
echo Step 1: Creating VPC
echo ====================================================
REM Check if VPC already exists
for /f "tokens=*" %%i in ('aws ec2 describe-vpcs --filters "Name=tag:Name,Values=%PREFIX%-vpc" --query "Vpcs[0].VpcId" --output text 2^>nul') do set EXISTING_VPC=%%i
if "%EXISTING_VPC%"=="None" set EXISTING_VPC=
if not "%EXISTING_VPC%"=="" (
    set VPC_ID=%EXISTING_VPC%
    echo VPC already exists: %VPC_ID%
) else (
    for /f "tokens=*" %%i in ('aws ec2 create-vpc --cidr-block %VPC_CIDR% --tag-specifications "ResourceType=vpc,Tags=[{Key=Name,Value=%PREFIX%-vpc}]" --query "Vpc.VpcId" --output text') do set VPC_ID=%%i
    echo VPC Created: %VPC_ID%
)

REM Enable DNS support and DNS hostnames
echo Enabling DNS support and hostnames for VPC...
aws ec2 modify-vpc-attribute --vpc-id %VPC_ID% --enable-dns-support
aws ec2 modify-vpc-attribute --vpc-id %VPC_ID% --enable-dns-hostnames

echo.
echo ====================================================
echo Step 2: Creating/Finding Internet Gateway
echo ====================================================
REM Check if Internet Gateway already exists
for /f "tokens=*" %%i in ('aws ec2 describe-internet-gateways --filters "Name=tag:Name,Values=%PREFIX%-igw" --query "InternetGateways[0].InternetGatewayId" --output text 2^>nul') do set EXISTING_IGW=%%i
if "%EXISTING_IGW%"=="None" set EXISTING_IGW=

if not "%EXISTING_IGW%"=="" (
    set IGW_ID=%EXISTING_IGW%
    echo Internet Gateway already exists: %IGW_ID%
) else (
    REM Check for available unattached Internet Gateway
    for /f "tokens=*" %%i in ('aws ec2 describe-internet-gateways --filters "Name=attachment.state,Values=available" --query "InternetGateways[0].InternetGatewayId" --output text 2^>nul') do set AVAILABLE_IGW=%%i
    if "%AVAILABLE_IGW%"=="None" set AVAILABLE_IGW=
    
    if not "%AVAILABLE_IGW%"=="" (
        set IGW_ID=%AVAILABLE_IGW%
        echo Using existing available Internet Gateway: %IGW_ID%
        REM Tag the existing gateway
        aws ec2 create-tags --resources %IGW_ID% --tags Key=Name,Value=%PREFIX%-igw
    ) else (
        echo Creating new Internet Gateway...
        for /f "tokens=*" %%i in ('aws ec2 create-internet-gateway --tag-specifications "ResourceType=internet-gateway,Tags=[{Key=Name,Value=%PREFIX%-igw}]" --query "InternetGateway.InternetGatewayId" --output text') do set IGW_ID=%%i
        echo Internet Gateway Created: %IGW_ID%
    )
)

REM Check if Internet Gateway is already attached to VPC
for /f "tokens=*" %%i in ('aws ec2 describe-internet-gateways --internet-gateway-ids %IGW_ID% --query "InternetGateways[0].Attachments[0].VpcId" --output text 2^>nul') do set ATTACHED_VPC=%%i
if "%ATTACHED_VPC%"=="None" set ATTACHED_VPC=

if "%ATTACHED_VPC%"=="%VPC_ID%" (
    echo Internet Gateway already attached to VPC
) else if not "%ATTACHED_VPC%"=="" (
    echo Detaching Internet Gateway from VPC: %ATTACHED_VPC%
    aws ec2 detach-internet-gateway --internet-gateway-id %IGW_ID% --vpc-id %ATTACHED_VPC%
    echo Attaching Internet Gateway to our VPC: %VPC_ID%
    aws ec2 attach-internet-gateway --internet-gateway-id %IGW_ID% --vpc-id %VPC_ID%
) else (
    echo Attaching Internet Gateway to VPC...
    aws ec2 attach-internet-gateway --internet-gateway-id %IGW_ID% --vpc-id %VPC_ID%
)

echo.
echo ====================================================
echo Step 3: Creating Public Subnet
echo ====================================================
REM Check if Subnet already exists
for /f "tokens=*" %%i in ('aws ec2 describe-subnets --filters "Name=tag:Name,Values=%PREFIX%-public-subnet" --query "Subnets[0].SubnetId" --output text 2^>nul') do set EXISTING_SUBNET=%%i
if "%EXISTING_SUBNET%"=="None" set EXISTING_SUBNET=
if not "%EXISTING_SUBNET%"=="" (
    set SUBNET_ID=%EXISTING_SUBNET%
    echo Public Subnet already exists: %SUBNET_ID%
) else (
    for /f "tokens=*" %%i in ('aws ec2 create-subnet --vpc-id %VPC_ID% --cidr-block %SUBNET_CIDR% --availability-zone %AZ% --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=%PREFIX%-public-subnet}]" --query "Subnet.SubnetId" --output text') do set SUBNET_ID=%%i
    echo Public Subnet Created: %SUBNET_ID%
)

REM Enable auto-assign public IP for subnet
echo Enabling auto-assign public IP for subnet...
aws ec2 modify-subnet-attribute --subnet-id %SUBNET_ID% --map-public-ip-on-launch

echo.
echo ====================================================
echo Step 4: Creating Route Table
echo ====================================================
REM Check if Route Table already exists
for /f "tokens=*" %%i in ('aws ec2 describe-route-tables --filters "Name=tag:Name,Values=%PREFIX%-public-rt" --query "RouteTables[0].RouteTableId" --output text 2^>nul') do set EXISTING_RT=%%i
if "%EXISTING_RT%"=="None" set EXISTING_RT=
if not "%EXISTING_RT%"=="" (
    set RT_ID=%EXISTING_RT%
    echo Route Table already exists: %RT_ID%
) else (
    for /f "tokens=*" %%i in ('aws ec2 create-route-table --vpc-id %VPC_ID% --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=%PREFIX%-public-rt}]" --query "RouteTable.RouteTableId" --output text') do set RT_ID=%%i
    echo Route Table Created: %RT_ID%
)

REM Check if route to Internet Gateway exists
for /f "tokens=*" %%i in ('aws ec2 describe-route-tables --route-table-ids %RT_ID% --query "RouteTables[0].Routes[?GatewayId==`%IGW_ID%`].GatewayId" --output text 2^>nul') do set EXISTING_ROUTE=%%i
if "%EXISTING_ROUTE%"=="None" set EXISTING_ROUTE=
if not "%EXISTING_ROUTE%"=="" (
    echo Route to Internet Gateway already exists
) else (
    echo Adding route to Internet Gateway...
    aws ec2 create-route --route-table-id %RT_ID% --destination-cidr-block 0.0.0.0/0 --gateway-id %IGW_ID%
)

REM Check if route table is associated with subnet
for /f "tokens=*" %%i in ('aws ec2 describe-route-tables --route-table-ids %RT_ID% --query "RouteTables[0].Associations[?SubnetId==`%SUBNET_ID%`].SubnetId" --output text 2^>nul') do set EXISTING_ASSOC=%%i
if "%EXISTING_ASSOC%"=="None" set EXISTING_ASSOC=
if not "%EXISTING_ASSOC%"=="" (
    echo Route table already associated with subnet
) else (
    echo Associating route table with subnet...
    aws ec2 associate-route-table --subnet-id %SUBNET_ID% --route-table-id %RT_ID%
)

echo.
echo ====================================================
echo Step 5: Creating Security Group
echo ====================================================
REM Check if Security Group already exists
for /f "tokens=*" %%i in ('aws ec2 describe-security-groups --filters "Name=tag:Name,Values=%PREFIX%-sg" --query "SecurityGroups[0].GroupId" --output text 2^>nul') do set EXISTING_SG=%%i
if "%EXISTING_SG%"=="None" set EXISTING_SG=
if not "%EXISTING_SG%"=="" (
    set SG_ID=%EXISTING_SG%
    echo Security Group already exists: %SG_ID%
) else (
    for /f "tokens=*" %%i in ('aws ec2 create-security-group --group-name %PREFIX%-security-group --description "Security group for %PREFIX% Flask application" --vpc-id %VPC_ID% --tag-specifications "ResourceType=security-group,Tags=[{Key=Name,Value=%PREFIX%-sg}]" --query "GroupId" --output text') do set SG_ID=%%i
    echo Security Group Created: %SG_ID%
)

REM Add security group rules (simplified approach)
echo Adding security group rules...

REM Add SSH access (port 22)
echo - Adding SSH (port 22) access...
aws ec2 authorize-security-group-ingress --group-id %SG_ID% --protocol tcp --port 22 --cidr 0.0.0.0/0 >nul 2>&1
if errorlevel 1 (
    echo   SSH access: ALREADY EXISTS
) else (
    echo   SSH access: ADDED
)

REM Add Flask application port 5000
echo - Adding Flask app (port 5000) access...
aws ec2 authorize-security-group-ingress --group-id %SG_ID% --protocol tcp --port 5000 --cidr 0.0.0.0/0 >nul 2>&1
if errorlevel 1 (
    echo   Flask app access: ALREADY EXISTS
) else (
    echo   Flask app access: ADDED
)

REM Add HTTP access (port 80)
echo - Adding HTTP (port 80) access...
aws ec2 authorize-security-group-ingress --group-id %SG_ID% --protocol tcp --port 80 --cidr 0.0.0.0/0 >nul 2>&1
if errorlevel 1 (
    echo   HTTP access: ALREADY EXISTS
) else (
    echo   HTTP access: ADDED
)

REM Add HTTPS access (port 443)
echo - Adding HTTPS (port 443) access...
aws ec2 authorize-security-group-ingress --group-id %SG_ID% --protocol tcp --port 443 --cidr 0.0.0.0/0 >nul 2>&1
if errorlevel 1 (
    echo   HTTPS access: ALREADY EXISTS
) else (
    echo   HTTPS access: ADDED
)

REM Add ICMP access (ping)
echo - Adding ICMP (ping) access...
aws ec2 authorize-security-group-ingress --group-id %SG_ID% --protocol icmp --port -1 --cidr 0.0.0.0/0 >nul 2>&1
if errorlevel 1 (
    echo   ICMP access: ALREADY EXISTS
) else (
    echo   ICMP access: ADDED
)

echo.
echo ====================================================
echo Step 6: Launching EC2 Instance
echo ====================================================
REM Check if EC2 Instance already exists and is running
for /f "tokens=*" %%i in ('aws ec2 describe-instances --filters "Name=tag:Name,Values=%PREFIX%-ec2-instance" "Name=instance-state-name,Values=running,pending" --query "Reservations[0].Instances[0].InstanceId" --output text 2^>nul') do set EXISTING_INSTANCE=%%i
if "%EXISTING_INSTANCE%"=="None" set EXISTING_INSTANCE=

if not "%EXISTING_INSTANCE%"=="" (
    set INSTANCE_ID=%EXISTING_INSTANCE%
    echo EC2 Instance already exists and is running: %INSTANCE_ID%
) else (
    echo Creating user data script for automatic setup...

    REM Create user data script for EC2 instance
    echo #!/bin/bash > user-data.sh
    echo # Update system >> user-data.sh
    echo yum update -y >> user-data.sh
    echo. >> user-data.sh
    echo # Install Python 3.11 and pip >> user-data.sh
    echo yum install -y python3.11 python3.11-pip git >> user-data.sh
    echo. >> user-data.sh
    echo # Create application directory >> user-data.sh
    echo mkdir -p /home/ec2-user/abhishek-thesis >> user-data.sh
    echo cd /home/ec2-user/abhishek-thesis >> user-data.sh
    echo. >> user-data.sh
    echo # Install required Python packages >> user-data.sh
    echo pip3.11 install flask pandas numpy scikit-learn plotly joblib >> user-data.sh
    echo. >> user-data.sh
    echo # Create a simple status page >> user-data.sh
    echo echo "EC2 Instance for Abhishek's Network Threat Detection System is ready!" ^> /home/ec2-user/status.txt >> user-data.sh
    echo echo "Access the application on port 5000 after uploading your Flask app" ^>^> /home/ec2-user/status.txt >> user-data.sh
    echo. >> user-data.sh
    echo # Set ownership >> user-data.sh
    echo chown -R ec2-user:ec2-user /home/ec2-user/ >> user-data.sh

    for /f "tokens=*" %%i in ('aws ec2 run-instances --image-id %AMI_ID% --count 1 --instance-type %INSTANCE_TYPE% --key-name %KEY_PAIR% --security-group-ids %SG_ID% --subnet-id %SUBNET_ID% --user-data file://user-data.sh --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=%PREFIX%-ec2-instance}]" --query "Instances[0].InstanceId" --output text') do set INSTANCE_ID=%%i
    echo EC2 Instance Launched: %INSTANCE_ID%
)

echo.
echo ====================================================
echo Getting Instance Details...
echo ====================================================
echo Waiting for instance to be in running state...
aws ec2 wait instance-running --instance-ids %INSTANCE_ID%

for /f "tokens=*" %%i in ('aws ec2 describe-instances --instance-ids %INSTANCE_ID% --query "Reservations[0].Instances[0].PublicIpAddress" --output text') do set PUBLIC_IP=%%i
for /f "tokens=*" %%i in ('aws ec2 describe-instances --instance-ids %INSTANCE_ID% --query "Reservations[0].Instances[0].PublicDnsName" --output text') do set PUBLIC_DNS=%%i

echo.
echo ====================================================
echo 🎉 AWS Infrastructure Setup Complete! 🎉
echo ====================================================
echo.
echo VPC ID:                %VPC_ID%
echo Subnet ID:             %SUBNET_ID%
echo Internet Gateway ID:   %IGW_ID%
echo Route Table ID:        %RT_ID%
echo Security Group ID:     %SG_ID%
echo Instance ID:           %INSTANCE_ID%
echo Public IP:             %PUBLIC_IP%
echo Public DNS:            %PUBLIC_DNS%
echo.

REM Save infrastructure details to file
echo ====================================================
echo Saving infrastructure details to file...
echo ====================================================
set DETAILS_FILE=aws-infrastructure-details.txt
set TIMESTAMP=%DATE% %TIME%

echo ================================================== > %DETAILS_FILE%
echo AWS Infrastructure Details for Abhishek's Project >> %DETAILS_FILE%
echo Created/Updated: %TIMESTAMP% >> %DETAILS_FILE%
echo Region: %REGION% >> %DETAILS_FILE%
echo Availability Zone: %AZ% >> %DETAILS_FILE%
echo ================================================== >> %DETAILS_FILE%
echo. >> %DETAILS_FILE%
echo RESOURCE IDENTIFIERS: >> %DETAILS_FILE%
echo ===================== >> %DETAILS_FILE%
echo VPC ID:                %VPC_ID% >> %DETAILS_FILE%
echo Subnet ID:             %SUBNET_ID% >> %DETAILS_FILE%
echo Internet Gateway ID:   %IGW_ID% >> %DETAILS_FILE%
echo Route Table ID:        %RT_ID% >> %DETAILS_FILE%
echo Security Group ID:     %SG_ID% >> %DETAILS_FILE%
echo Instance ID:           %INSTANCE_ID% >> %DETAILS_FILE%
echo. >> %DETAILS_FILE%
echo NETWORK DETAILS: >> %DETAILS_FILE%
echo ================ >> %DETAILS_FILE%
echo Public IP:             %PUBLIC_IP% >> %DETAILS_FILE%
echo Public DNS:            %PUBLIC_DNS% >> %DETAILS_FILE%
echo VPC CIDR:              %VPC_CIDR% >> %DETAILS_FILE%
echo Subnet CIDR:           %SUBNET_CIDR% >> %DETAILS_FILE%
echo. >> %DETAILS_FILE%
echo INSTANCE SPECIFICATIONS: >> %DETAILS_FILE%
echo ======================== >> %DETAILS_FILE%
echo AMI ID:                %AMI_ID% >> %DETAILS_FILE%
echo Instance Type:         %INSTANCE_TYPE% >> %DETAILS_FILE%
echo Key Pair:              %KEY_PAIR%.pem >> %DETAILS_FILE%
echo. >> %DETAILS_FILE%
echo SECURITY GROUP RULES: >> %DETAILS_FILE%
echo ===================== >> %DETAILS_FILE%
echo - SSH (22): 0.0.0.0/0 >> %DETAILS_FILE%
echo - Flask App (5000): 0.0.0.0/0 >> %DETAILS_FILE%
echo - HTTP (80): 0.0.0.0/0 >> %DETAILS_FILE%
echo - HTTPS (443): 0.0.0.0/0 >> %DETAILS_FILE%
echo - ICMP (ping): 0.0.0.0/0 >> %DETAILS_FILE%
echo. >> %DETAILS_FILE%
echo CONNECTION COMMANDS: >> %DETAILS_FILE%
echo ==================== >> %DETAILS_FILE%
echo SSH Command: >> %DETAILS_FILE%
echo   ssh -i %KEY_PAIR%.pem ec2-user@%PUBLIC_IP% >> %DETAILS_FILE%
echo. >> %DETAILS_FILE%
echo SCP Upload Command: >> %DETAILS_FILE%
echo   scp -i %KEY_PAIR%.pem -r . ec2-user@%PUBLIC_IP%:/home/ec2-user/abhishek-thesis/ >> %DETAILS_FILE%
echo. >> %DETAILS_FILE%
echo Flask Application URL: >> %DETAILS_FILE%
echo   http://%PUBLIC_IP%:5000 >> %DETAILS_FILE%
echo. >> %DETAILS_FILE%
echo CLEANUP COMMAND: >> %DETAILS_FILE%
echo ================ >> %DETAILS_FILE%
echo To delete all resources: >> %DETAILS_FILE%
echo   cleanup-aws-infrastructure.bat >> %DETAILS_FILE%
echo. >> %DETAILS_FILE%
echo AWS CLI COMMANDS FOR MANUAL MANAGEMENT: >> %DETAILS_FILE%
echo ======================================= >> %DETAILS_FILE%
echo View VPC: >> %DETAILS_FILE%
echo   aws ec2 describe-vpcs --vpc-ids %VPC_ID% >> %DETAILS_FILE%
echo. >> %DETAILS_FILE%
echo View Instance: >> %DETAILS_FILE%
echo   aws ec2 describe-instances --instance-ids %INSTANCE_ID% >> %DETAILS_FILE%
echo. >> %DETAILS_FILE%
echo View Security Group: >> %DETAILS_FILE%
echo   aws ec2 describe-security-groups --group-ids %SG_ID% >> %DETAILS_FILE%
echo. >> %DETAILS_FILE%
echo Start Instance: >> %DETAILS_FILE%
echo   aws ec2 start-instances --instance-ids %INSTANCE_ID% >> %DETAILS_FILE%
echo. >> %DETAILS_FILE%
echo Stop Instance: >> %DETAILS_FILE%
echo   aws ec2 stop-instances --instance-ids %INSTANCE_ID% >> %DETAILS_FILE%
echo. >> %DETAILS_FILE%
echo Reboot Instance: >> %DETAILS_FILE%
echo   aws ec2 reboot-instances --instance-ids %INSTANCE_ID% >> %DETAILS_FILE%
echo. >> %DETAILS_FILE%
echo ================================================== >> %DETAILS_FILE%
echo End of Infrastructure Details >> %DETAILS_FILE%
echo ================================================== >> %DETAILS_FILE%

echo Infrastructure details saved to: %DETAILS_FILE%
echo.

REM Create JSON export for programmatic access
set JSON_FILE=aws-infrastructure.json
echo Creating JSON export: %JSON_FILE%
echo { > %JSON_FILE%
echo   "timestamp": "%TIMESTAMP%", >> %JSON_FILE%
echo   "region": "%REGION%", >> %JSON_FILE%
echo   "availability_zone": "%AZ%", >> %JSON_FILE%
echo   "vpc": { >> %JSON_FILE%
echo     "id": "%VPC_ID%", >> %JSON_FILE%
echo     "cidr": "%VPC_CIDR%" >> %JSON_FILE%
echo   }, >> %JSON_FILE%
echo   "subnet": { >> %JSON_FILE%
echo     "id": "%SUBNET_ID%", >> %JSON_FILE%
echo     "cidr": "%SUBNET_CIDR%" >> %JSON_FILE%
echo   }, >> %JSON_FILE%
echo   "internet_gateway": { >> %JSON_FILE%
echo     "id": "%IGW_ID%" >> %JSON_FILE%
echo   }, >> %JSON_FILE%
echo   "route_table": { >> %JSON_FILE%
echo     "id": "%RT_ID%" >> %JSON_FILE%
echo   }, >> %JSON_FILE%
echo   "security_group": { >> %JSON_FILE%
echo     "id": "%SG_ID%", >> %JSON_FILE%
echo     "rules": [ >> %JSON_FILE%
echo       {"protocol": "tcp", "port": 22, "source": "0.0.0.0/0", "description": "SSH"}, >> %JSON_FILE%
echo       {"protocol": "tcp", "port": 5000, "source": "0.0.0.0/0", "description": "Flask App"}, >> %JSON_FILE%
echo       {"protocol": "tcp", "port": 80, "source": "0.0.0.0/0", "description": "HTTP"}, >> %JSON_FILE%
echo       {"protocol": "tcp", "port": 443, "source": "0.0.0.0/0", "description": "HTTPS"}, >> %JSON_FILE%
echo       {"protocol": "icmp", "port": -1, "source": "0.0.0.0/0", "description": "ICMP"} >> %JSON_FILE%
echo     ] >> %JSON_FILE%
echo   }, >> %JSON_FILE%
echo   "instance": { >> %JSON_FILE%
echo     "id": "%INSTANCE_ID%", >> %JSON_FILE%
echo     "type": "%INSTANCE_TYPE%", >> %JSON_FILE%
echo     "ami": "%AMI_ID%", >> %JSON_FILE%
echo     "key_pair": "%KEY_PAIR%", >> %JSON_FILE%
echo     "public_ip": "%PUBLIC_IP%", >> %JSON_FILE%
echo     "public_dns": "%PUBLIC_DNS%" >> %JSON_FILE%
echo   }, >> %JSON_FILE%
echo   "urls": { >> %JSON_FILE%
echo     "flask_app": "http://%PUBLIC_IP%:5000", >> %JSON_FILE%
echo     "ssh": "ssh -i %KEY_PAIR%.pem ec2-user@%PUBLIC_IP%" >> %JSON_FILE%
echo   } >> %JSON_FILE%
echo } >> %JSON_FILE%

echo JSON export saved to: %JSON_FILE%
echo.
echo ====================================================
echo Next Steps:
echo ====================================================
echo.
echo 1. Connect to your EC2 instance via SSH:
echo    ssh -i ec2keypair.pem ec2-user@%PUBLIC_IP%
echo.
echo 2. Upload your Flask application files to the instance:
echo    scp -i ec2keypair.pem -r . ec2-user@%PUBLIC_IP%:/home/ec2-user/abhishek-thesis/
echo.
echo 3. Access your Flask application at:
echo    http://%PUBLIC_IP%:5000
echo.
echo 4. To check instance status:
echo    cat /home/ec2-user/status.txt
echo.
echo ====================================================
echo Security Group Rules Configured:
echo ====================================================
echo - SSH (22): 0.0.0.0/0
echo - Flask App (5000): 0.0.0.0/0
echo - HTTP (80): 0.0.0.0/0
echo - HTTPS (443): 0.0.0.0/0
echo - ICMP (ping): 0.0.0.0/0
echo.
echo Auto-assign public IP: ENABLED
echo AMI: Amazon Linux 2023 AMI 2023.8.20250804.0 x86_64 HVM kernel-6.1
echo Instance Type: t3.micro
echo Key Pair: ec2keypair.pem
echo.

REM Clean up temporary files
del user-data.sh

echo ====================================================
echo Infrastructure setup completed successfully!
echo Save this information for future reference.
echo ====================================================
pause
