"""
Email service for sending OTP codes, password reset emails, and notifications.
Uses async SMTP with Jinja2 templates for professional email formatting.
"""

import aiosmtplib
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
from jinja2 import Environment, BaseLoader
from app.core.config import settings
import logging
from typing import Optional, Dict, Any
from datetime import datetime, UTC

# Set up logging
logger = logging.getLogger(__name__)

class EmailService:
    """
    Service for sending emails with templates and SMTP configuration.
    """
    
    def __init__(self):
        """Initialize email service with Jinja2 environment for templates."""
        # Create Jinja2 environment for email templates
        self.jinja_env = Environment(loader=BaseLoader())
    
    async def send_email(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: Optional[str] = None
    ) -> bool:
        """
        Send an email using SMTP.
        
        Args:
            to_email: Recipient email address
            subject: Email subject line
            html_content: HTML email content
            text_content: Plain text email content (optional)
            
        Returns:
            True if email sent successfully, False otherwise
        """
        try:
            # Create email message
            message = MimeMultipart("alternative")
            message["Subject"] = subject
            message["From"] = f"{settings.from_name} <{settings.from_email}>"
            message["To"] = to_email
            
            # Add text content if provided
            if text_content:
                text_part = MimeText(text_content, "plain")
                message.attach(text_part)
            
            # Add HTML content
            html_part = MimeText(html_content, "html")
            message.attach(html_part)
            
            # Connect to SMTP server and send email
            async with aiosmtplib.SMTP(
                hostname=settings.smtp_host,
                port=settings.smtp_port,
                start_tls=True  # Use TLS encryption
            ) as smtp:
                # Login to SMTP server
                await smtp.login(settings.smtp_username, settings.smtp_password)
                
                # Send the email
                await smtp.send_message(message)
                
                logger.info(f"Email sent successfully to {to_email}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {e}")
            return False
    
    def render_template(self, template_string: str, context: Dict[str, Any]) -> str:
        """
        Render email template with context data.
        
        Args:
            template_string: Jinja2 template string
            context: Data to render in template
            
        Returns:
            Rendered template string
        """
        template = self.jinja_env.from_string(template_string)
        return template.render(**context)
    
    async def send_otp_email(
        self,
        email: str,
        name: str,
        otp_code: str,
        purpose: str = "verify your email"
    ) -> bool:
        """
        Send OTP verification email.
        
        Args:
            email: Recipient email address
            name: Recipient's name
            otp_code: 6-digit OTP code
            purpose: Purpose of the OTP (e.g., "verify your email", "reset your password")
            
        Returns:
            True if email sent successfully, False otherwise
        """
        # Email subject
        subject = f"Your {settings.app_name} Verification Code"
        
        # Email context data
        context = {
            "name": name,
            "otp_code": otp_code,
            "purpose": purpose,
            "app_name": settings.app_name,
            "frontend_url": settings.frontend_url,
            "expire_minutes": settings.otp_expire_minutes,
            "year": datetime.now(UTC).year
        }
        
        # HTML email template
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{{ app_name }} - Verification Code</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 0; background-color: #f4f4f4; }
                .container { max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 20px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }
                .header { text-align: center; padding: 20px 0; border-bottom: 1px solid #eee; }
                .logo { font-size: 24px; font-weight: bold; color: #2563eb; }
                .content { padding: 30px 0; text-align: center; }
                .otp-code { font-size: 32px; font-weight: bold; color: #2563eb; background-color: #f8fafc; padding: 20px; border-radius: 8px; letter-spacing: 4px; margin: 20px 0; border: 2px dashed #2563eb; }
                .warning { background-color: #fef3cd; border: 1px solid #fde047; border-radius: 6px; padding: 15px; margin: 20px 0; color: #92400e; }
                .footer { text-align: center; padding: 20px 0; border-top: 1px solid #eee; color: #6b7280; font-size: 14px; }
                .btn { display: inline-block; background-color: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin: 10px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="logo">{{ app_name }}</div>
                </div>
                
                <div class="content">
                    <h1>Hi {{ name }}!</h1>
                    <p>You requested to {{ purpose }}. Please use the verification code below:</p>
                    
                    <div class="otp-code">{{ otp_code }}</div>
                    
                    <p>This code will expire in <strong>{{ expire_minutes }} minutes</strong>.</p>
                    
                    <div class="warning">
                        <strong>Security Notice:</strong> Never share this code with anyone. {{ app_name }} will never ask for your verification code via phone, email, or any other method.
                    </div>
                    
                    <p>If you didn't request this code, you can safely ignore this email.</p>
                    
                    <a href="{{ frontend_url }}" class="btn">Go to {{ app_name }}</a>
                </div>
                
                <div class="footer">
                    <p>&copy; {{ year }} {{ app_name }}. All rights reserved.</p>
                    <p>This is an automated message, please do not reply to this email.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Plain text template (fallback)
        text_template = """
        Hi {{ name }}!
        
        You requested to {{ purpose }}. Please use the verification code below:
        
        {{ otp_code }}
        
        This code will expire in {{ expire_minutes }} minutes.
        
        Security Notice: Never share this code with anyone. {{ app_name }} will never ask for your verification code via phone, email, or any other method.
        
        If you didn't request this code, you can safely ignore this email.
        
        Visit {{ frontend_url }} to continue.
        
        © {{ year }} {{ app_name }}. All rights reserved.
        This is an automated message, please do not reply to this email.
        """
        
        # Render templates
        html_content = self.render_template(html_template, context)
        text_content = self.render_template(text_template, context)
        
        # Send email
        return await self.send_email(email, subject, html_content, text_content)
    
    async def send_password_reset_email(
        self,
        email: str,
        name: str,
        reset_token: str
    ) -> bool:
        """
        Send password reset email with secure link.
        
        Args:
            email: Recipient email address
            name: Recipient's name
            reset_token: Password reset JWT token
            
        Returns:
            True if email sent successfully, False otherwise
        """
        # Email subject
        subject = f"Reset Your {settings.app_name} Password"
        
        # Create reset link
        reset_link = f"{settings.frontend_url}/reset-password?token={reset_token}"
        
        # Email context data
        context = {
            "name": name,
            "reset_link": reset_link,
            "app_name": settings.app_name,
            "frontend_url": settings.frontend_url,
            "year": datetime.now(UTC).year
        }
        
        # HTML email template
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{{ app_name }} - Password Reset</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 0; background-color: #f4f4f4; }
                .container { max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 20px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }
                .header { text-align: center; padding: 20px 0; border-bottom: 1px solid #eee; }
                .logo { font-size: 24px; font-weight: bold; color: #dc2626; }
                .content { padding: 30px 0; text-align: center; }
                .warning { background-color: #fef2f2; border: 1px solid #fca5a5; border-radius: 6px; padding: 15px; margin: 20px 0; color: #991b1b; }
                .footer { text-align: center; padding: 20px 0; border-top: 1px solid #eee; color: #6b7280; font-size: 14px; }
                .btn { display: inline-block; background-color: #dc2626; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin: 20px 0; }
                .btn:hover { background-color: #b91c1c; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="logo">{{ app_name }}</div>
                </div>
                
                <div class="content">
                    <h1>Password Reset Request</h1>
                    <p>Hi {{ name }},</p>
                    <p>We received a request to reset your password for your {{ app_name }} account.</p>
                    
                    <a href="{{ reset_link }}" class="btn">Reset Your Password</a>
                    
                    <p>This link will expire in 30 minutes for security reasons.</p>
                    
                    <div class="warning">
                        <strong>Security Notice:</strong> If you didn't request this password reset, please ignore this email or contact our support team if you have concerns about your account security.
                    </div>
                    
                    <p>For security reasons, this link can only be used once.</p>
                </div>
                
                <div class="footer">
                    <p>&copy; {{ year }} {{ app_name }}. All rights reserved.</p>
                    <p>This is an automated message, please do not reply to this email.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Plain text template
        text_template = """
        Password Reset Request
        
        Hi {{ name }},
        
        We received a request to reset your password for your {{ app_name }} account.
        
        Click the link below to reset your password:
        {{ reset_link }}
        
        This link will expire in 30 minutes for security reasons.
        
        Security Notice: If you didn't request this password reset, please ignore this email or contact our support team if you have concerns about your account security.
        
        For security reasons, this link can only be used once.
        
        © {{ year }} {{ app_name }}. All rights reserved.
        This is an automated message, please do not reply to this email.
        """
        
        # Render templates
        html_content = self.render_template(html_template, context)
        text_content = self.render_template(text_template, context)
        
        # Send email
        return await self.send_email(email, subject, html_content, text_content)
    
    async def send_welcome_email(
        self,
        email: str,
        name: str,
        identity: str
    ) -> bool:
        """
        Send welcome email after successful registration.
        
        Args:
            email: Recipient email address
            name: Recipient's name
            identity: User's role (broker/builder/customer)
            
        Returns:
            True if email sent successfully, False otherwise
        """
        # Email subject
        subject = f"Welcome to {settings.app_name}!"
        
        # Email context data
        context = {
            "name": name,
            "identity": identity.title(),
            "app_name": settings.app_name,
            "frontend_url": settings.frontend_url,
            "year": datetime.now(UTC).year
        }
        
        # HTML email template
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Welcome to {{ app_name }}</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 0; background-color: #f4f4f4; }
                .container { max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 20px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }
                .header { text-align: center; padding: 20px 0; border-bottom: 1px solid #eee; }
                .logo { font-size: 24px; font-weight: bold; color: #059669; }
                .content { padding: 30px 0; text-align: center; }
                .footer { text-align: center; padding: 20px 0; border-top: 1px solid #eee; color: #6b7280; font-size: 14px; }
                .btn { display: inline-block; background-color: #059669; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin: 20px 0; }
                .feature { background-color: #f0fdf4; border-radius: 6px; padding: 15px; margin: 10px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="logo">{{ app_name }}</div>
                </div>
                
                <div class="content">
                    <h1>Welcome to {{ app_name }}, {{ name }}! 🎉</h1>
                    <p>Thank you for joining us as a <strong>{{ identity }}</strong>. Your account has been successfully created and verified.</p>
                    
                    <div class="feature">
                        <h3>What's Next?</h3>
                        <p>Start exploring our platform and connect with other professionals in the construction industry.</p>
                    </div>
                    
                    <a href="{{ frontend_url }}/dashboard" class="btn">Go to Dashboard</a>
                    
                    <p>If you have any questions, feel free to reach out to our support team.</p>
                </div>
                
                <div class="footer">
                    <p>&copy; {{ year }} {{ app_name }}. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Plain text template
        text_template = """
        Welcome to {{ app_name }}, {{ name }}!
        
        Thank you for joining us as a {{ identity }}. Your account has been successfully created and verified.
        
        What's Next?
        Start exploring our platform and connect with other professionals in the construction industry.
        
        Visit {{ app_name }} to get started.
        
        If you have any questions, feel free to reach out to our support team.
        
        © {{ year }} {{ app_name }}. All rights reserved.
        """
        
        # Render templates
        html_content = self.render_template(html_template, context)
        text_content = self.render_template(text_template, context)
        
        # Send email
        return await self.send_email(email, subject, html_content, text_content)

# Create global instance
email_service = EmailService()