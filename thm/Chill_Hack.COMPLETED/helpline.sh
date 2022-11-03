#!/bin/bash 
echo 
echo "Welcome to helpdesk. Feel free to talk to anyone at any time!" 
echo 
read -p "Enter the person whom you want to talk with: " person 
read -p "Hello user! I am $person, Please enter your message: " msg 
$msg 2>/dev/null 
echo "Thank you for your precious time!" 