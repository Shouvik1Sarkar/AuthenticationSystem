import { body } from "express-validator";

const userRegister = () => {
  return [
    body("userName")
      .notEmpty()
      .withMessage("userName field is required")
      .bail()
      .trim()
      .toLowerCase()
      .isLength({ min: 6 })
      .withMessage("UserName must contain at least 6 characters")
      .bail()
      .isLength({ max: 15 })
      .withMessage("UserName can not contain more than 15 characters"),
    body("email")
      .notEmpty()
      .withMessage("email field is required")
      .bail()
      .trim()
      .toLowerCase()
      .isEmail()
      .withMessage("Invalid email"),

    body("password")
      .trim()
      .notEmpty()
      .withMessage("Password field can not be empty")
      .bail()
      .isLength({ min: 6 })
      .withMessage("Password must contain at least 6 characters")
      .bail()
      .isLength({ max: 22 })
      .withMessage("Password can not contain more than 15 characters"),
  ];
};
export { userRegister };
