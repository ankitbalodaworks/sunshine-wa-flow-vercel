import { useState } from 'react';

export default function WhatsappFlow() {
  const [step, setStep] = useState('APPOINTMENT');
  const [form, setForm] = useState({});
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);

  // Example data from your flow JSON
  const departments = [
    { id: 'shopping', title: 'Shopping & Groceries' },
    { id: 'clothing', title: 'Clothing & Apparel' },
    { id: 'home', title: 'Home Goods & Decor' },
    { id: 'electronics', title: 'Electronics & Appliances' },
    { id: 'beauty', title: 'Beauty & Personal Care' }
  ];
  const locations = [
    { id: '1', title: 'King’s Cross, London' },
    { id: '2', title: 'Oxford Street, London' },
    { id: '3', title: 'Covent Garden, London' },
    { id: '4', title: 'Piccadilly Circus, London' }
  ];
  const dates = [
    { id: '2024-01-01', title: 'Mon Jan 01 2024' },
    { id: '2024-01-02', title: 'Tue Jan 02 2024' },
    { id: '2024-01-03', title: 'Wed Jan 03 2024' }
  ];
  const times = [
    { id: '10:30', title: '10:30' },
    { id: '11:00', title: '11:00' },
    { id: '11:30', title: '11:30' },
    { id: '12:00', title: '12:00' },
    { id: '12:30', title: '12:30' }
  ];

  // Handlers for each step
  const handleAppointmentSubmit = (e) => {
    e.preventDefault();
    setStep('DETAILS');
  };

  const handleDetailsSubmit = (e) => {
    e.preventDefault();
    setStep('SUMMARY');
  };

  const handleSummarySubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    // Send data to API
    const res = await fetch('/api/saveAppointment', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(form)
    });
    setLoading(false);
    if (res.ok) setSuccess(true);
  };

  // Render forms based on step
  if (success) return <div>Appointment saved! Thank you.</div>;

  return (
    <div style={{ maxWidth: 500, margin: 'auto' }}>
      {step === 'APPOINTMENT' && (
        <form onSubmit={handleAppointmentSubmit}>
          <h2>Appointment</h2>
          <label>Department</label>
          <select required onChange={e => setForm(f => ({ ...f, department: e.target.value }))}>
            <option value="">Select</option>
            {departments.map(d => <option key={d.id} value={d.id}>{d.title}</option>)}
          </select>
          <label>Location</label>
          <select required onChange={e => setForm(f => ({ ...f, location: e.target.value }))}>
            <option value="">Select</option>
            {locations.map(l => <option key={l.id} value={l.id}>{l.title}</option>)}
          </select>
          <label>Date</label>
          <select required onChange={e => setForm(f => ({ ...f, date: e.target.value }))}>
            <option value="">Select</option>
            {dates.map(d => <option key={d.id} value={d.id}>{d.title}</option>)}
          </select>
          <label>Time</label>
          <select required onChange={e => setForm(f => ({ ...f, time: e.target.value }))}>
            <option value="">Select</option>
            {times.map(t => <option key={t.id} value={t.id}>{t.title}</option>)}
          </select>
          <button type="submit">Continue</button>
        </form>
      )}
      {step === 'DETAILS' && (
        <form onSubmit={handleDetailsSubmit}>
          <h2>Details</h2>
          <label>Name</label>
          <input required onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
          <label>Email</label>
          <input type="email" required onChange={e => setForm(f => ({ ...f, email: e.target.value }))} />
          <label>Phone</label>
          <input type="tel" required onChange={e => setForm(f => ({ ...f, phone: e.target.value }))} />
          <label>Further details</label>
          <textarea onChange={e => setForm(f => ({ ...f, more_details: e.target.value }))} />
          <button type="submit">Continue</button>
        </form>
      )}
      {step === 'SUMMARY' && (
        <form onSubmit={handleSummarySubmit}>
          <h2>Summary</h2>
          <div>
            <strong>Department:</strong> {form.department}<br />
            <strong>Location:</strong> {form.location}<br />
            <strong>Date:</strong> {form.date}<br />
            <strong>Time:</strong> {form.time}<br />
            <strong>Name:</strong> {form.name}<br />
            <strong>Email:</strong> {form.email}<br />
            <strong>Phone:</strong> {form.phone}<br />
            <strong>Details:</strong> {form.more_details}
          </div>
          <label>
            <input type="checkbox" required /> I agree to the terms
          </label>
          <button type="submit" disabled={loading}>{loading ? 'Saving...' : 'Confirm Appointment'}</button>
        </form>
      )}
    </div>
  );
}
