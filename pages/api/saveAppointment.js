export default async function handler(req, res) {
  if (req.method === 'POST') {
    const appointmentData = req.body;
    // TODO: Save appointmentData to your database or storage
    // For demo, just log and return success
    console.log('Received appointment:', appointmentData);
    return res.status(200).json({ success: true });
  }
  res.status(405).json({ error: 'Method not allowed' });
}