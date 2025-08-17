import Mailgen from "mailgen";
import nodemailer from "nodemailer";

const mailSender = async (options) => {
  const mailGenerator = new Mailgen({
    theme: "default",
    product: {
      name: "Mailgen",
      link: "https://mailgen.js/",
    },
  });

  const emailBody = mailGenerator.generate(options.mailGenContent);
  const emailText = mailGenerator.generatePlaintext(options.mailGenContent);

  const transporter = nodemailer.createTransport({
    host: process.env.MAILTRAP_HOST,
    port: Number(process.env.MAILTRAP_PORT),
    // secure: Number(process.env.MAILTRAP_SECURE), // true for 465, false for other ports
    auth: {
      user: process.env.MAILTRAP_USER,
      pass: process.env.MAILTRAP_PASS,
    },
  });

  const mailInfo = {
    from: process.env.MAILTRAP_DESTINATION_EMAIL,
    to: options.email,
    subject: options.subject,
    text: emailText, // plain‑text body
    html: emailBody, // HTML body
  };

  try {
    await transporter.sendMail(mailInfo);
  } catch (error) {
    console.error("Mail sending error:", error.message);
    throw error;
  }
};

const registrationEmail = (name, senderUrl) => {
  return {
    body: {
      name: name,
      intro: "Welcome to the authentication System",
      action: {
        instructions: "Click on the URL to get yourself verified.",
        button: {
          color: "#22BC66", // Optional action button color
          text: "Confirm your account",
          link: senderUrl,
        },
      },
      outro:
        "Need help, or have questions? Just reply to this email, we'd love to help.",
    },
  };
};

const forgotPasswordEmail = (name, senderUrl) => {
  return {
    body: {
      name: name,
      intro: "Welcome to the authentication System",
      action: {
        instructions: "Click on the URL to reset Password.",
        button: {
          color: "#22BC66", // Optional action button color
          text: "Reset Password",
          link: senderUrl,
        },
      },
      outro:
        "Need help, or have questions? Just reply to this email, we'd love to help.",
    },
  };
};
const twoFactorEmail = (name, twoFacOTP) => {
  return {
    body: {
      name: name,
      intro: "Welcome to the authentication System",
      // action: {
      //   instructions: "This is 2factor token",
      //   // button: {
      //   //   color: "#22BC66", // Optional action button color
      //   //   text: "Reset Password",
      //   //   link: twoFacOTP,
      //   // },
      // },
      dictionary: {
        text: "Reset Password",
        link: twoFacOTP,
      },
      outro:
        "Need help, or have questions? Just reply to this email, we'd love to help.",
    },
  };
};

export default mailSender;
export { registrationEmail, forgotPasswordEmail, twoFactorEmail };
