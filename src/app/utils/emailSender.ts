import nodemailer from 'nodemailer';
import config from '../config';

export const emailSender = async (email: string, htmlText: string) => {
  // Create a test account or replace with real credentials.
  const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false, // true for 465, false for other ports
    auth: {
      user: config.email_for_mailer,
      pass: config.email_password,
    },
  });

  // Wrap in an async IIFE so we can use await.

  const info = await transporter.sendMail({
    from: '"project-start-up" <rashidsarkaroffice@gmail.com>',
    to: email,
    subject: 'Reset Your Password',
    // text: '  ', // plain‑text body
    html: htmlText,
  });

  console.log('Message sent:', info.messageId);
};
