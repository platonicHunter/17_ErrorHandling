const sum = (a, b) => {
  if (a && b) {
    return a + b;
  }
  throw new error("invalid argument");
};
try {
  console.log(sum(1,2));
} catch (err) {
  console.log(err);
}
