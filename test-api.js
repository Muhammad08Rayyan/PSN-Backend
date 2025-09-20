const axios = require('axios');

async function testJobsAPI() {
  try {
    console.log('Testing Jobs API endpoint...');

    // Test without authentication first
    const response = await axios.get('http://192.168.100.27:3000/api/jobs', {
      timeout: 10000
    });

    console.log('Response status:', response.status);
    console.log('Response data:', JSON.stringify(response.data, null, 2));

  } catch (error) {
    console.error('API Test failed:');
    console.error('Error status:', error.response?.status);
    console.error('Error message:', error.response?.data?.message || error.message);
    console.error('Error details:', error.response?.data);
  }
}

testJobsAPI();