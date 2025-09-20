const mongoose = require('mongoose');
require('dotenv').config();

// Full Job schema to check database
const jobSchema = new mongoose.Schema({
  title: { type: String, required: true },
  company: { type: String, required: true },
  location: { type: String, required: true },
  type: {
    type: String,
    enum: ['Full-time', 'Part-time', 'Contract', 'Locum'],
    default: 'Full-time'
  },
  salary: { type: String },
  description: { type: String, required: true },
  requirements: [{ type: String }],
  benefits: [{ type: String }],
  experience: { type: String, required: true },
  specialty: { type: String, required: true },
  hospital: { type: String },
  urgent: { type: Boolean, default: false },
  isEasyApply: { type: Boolean, default: false },
  applicants: { type: Number, default: 0 },
  companyLogo: { type: String },
  postedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Doctor' },
  isActive: { type: Boolean, default: true },
  expiryDate: { type: Date },
  contactEmail: { type: String },
  contactPhone: { type: String }
}, { timestamps: true, collection: 'jobs' });

const Job = mongoose.model('Job', jobSchema);

async function checkJobs() {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('Connected to MongoDB');

    const jobs = await Job.find({});
    console.log(`Found ${jobs.length} jobs in database`);

    jobs.forEach((job, i) => {
      console.log(`${i + 1}. ${job.title || 'No title'} - ${job.company || 'No company'}`);
    });

    await mongoose.disconnect();
  } catch (error) {
    console.error('Error:', error);
  }
}

checkJobs();