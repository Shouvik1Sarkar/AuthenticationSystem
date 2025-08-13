import mongoose from "mongoose";

const dbConnect = async (req, res) => {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log("mongodb connected properly");
  } catch (error) {
    console.log("MONGODB CONNECTION FAILED, ", error);
    throw error;
  }
};
export default dbConnect;
