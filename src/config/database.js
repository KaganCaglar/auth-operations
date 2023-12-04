const mongoose = require('mongoose');

mongoose.connect("mongodb+srv://cglr:cglr24@cluster0.vfgwmsv.mongodb.net")



const mongoose = require("mongoose");
mongoose.connect(
  "",
  {
    useNewUrlParser: true,
    useCreateIndex: true,
    useUnifiedTopology: true,
    useFindAndModify: false,
    serverSelectionTimeoutMS: 5000,
  }
);

mongoose.set("useNewUrlParser", true);
mongoose.set("useFindAndModify", false);
mongoose.set("useCreateIndex", true);