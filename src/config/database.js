const mongoose = require("mongoose");
mongoose.connect(
  "mongodb+srv://cglr24:cglr24@cluster0.doa5dkf.mongodb.net/",
  {
    useNewUrlParser: true,
    useCreateIndex: true,
    useUnifiedTopology: true,
    useFindAndModify: false,
  }
);

mongoose.set("useNewUrlParser", true);
mongoose.set("useFindAndModify", false);
mongoose.set("useCreateIndex", true);