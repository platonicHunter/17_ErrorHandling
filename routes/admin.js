
// Routes
const express = require("express");
const { body } = require("express-validator");
const adminController = require("../controllers/admin");
const isAuth = require("../middleware/is-auth");

const router = express.Router();

router.get("/add-product", isAuth, adminController.getAddProduct);
router.get("/products", isAuth, adminController.getProducts);

router.post(
  "/add-product",
  [
    body("title")
      .isAlphanumeric().withMessage('Title must be alphanumeric.')
      .isLength({ min: 3 }).withMessage('Title must be at least 3 characters long.')
      .trim(),
    body("imageUrl").isURL().withMessage('Image URL must be valid.'),
    body("price").isFloat().withMessage('Price must be a number.'),
    body("description")
      .isAlphanumeric().withMessage('Description must be alphanumeric.')
      .isLength({ min: 5, max: 400 }).withMessage('Description must be between 5 and 400 characters.')
      .trim()
  ],
  isAuth,
  adminController.postAddProduct
);

router.get("/edit-product/:productId", isAuth, adminController.getEditProduct);

router.post(
  '/edit-product',
  [
    body('title')
      .isString().withMessage('Title must be a string.')
      .isLength({ min: 3 }).withMessage('Title must be at least 3 characters long.')
      .trim(),
    body('imageUrl').isURL().withMessage('Image URL must be valid.'),
    body('price').isFloat().withMessage('Price must be a number.'),
    body('description')
      .isLength({ min: 5, max: 400 }).withMessage('Description must be between 5 and 400 characters.')
      .trim()
  ],
  isAuth,
  adminController.postEditProduct
);

router.post("/delete-product", isAuth, adminController.postDeleteProduct);

module.exports = router;
