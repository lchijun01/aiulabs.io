const stripe = require('stripe')(process.env.STRIPE_API_KEY);
const mysql = require('mysql2/promise'); // Use promise-based MySQL

// Database connection
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});

async function handleWebhook(req, res) {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
        // Construct event
        event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_API);
        console.log('Webhook event received:', event.type);
    } catch (err) {
        console.error('Webhook signature verification failed:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // Only handle checkout.session.completed
    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;

        console.log('Session Data:', JSON.stringify(session, null, 2));

        const customerId = session.customer;
        const subscriptionId = session.subscription;
        const userId = session.metadata.user_id; // user_id from metadata

        if (!customerId || !subscriptionId || !userId) {
            console.error('Missing required details:', { customerId, subscriptionId, userId });
            return res.status(400).send('Missing required details.');
        }

        try {
            // Retrieve subscription details
            const subscription = await stripe.subscriptions.retrieve(subscriptionId);
            const endDate = new Date(subscription.current_period_end * 1000);

            console.log('Subscription Retrieved:', { endDate, subscriptionId, customerId });

            // Update database
            const updateQuery = `
                UPDATE users
                SET stripe_customer_id = ?, subscription_status = 'active', subscription_end_date = ?
                WHERE id = ?
            `;

            const [result] = await db.query(updateQuery, [customerId, endDate, userId]);
            if (result.affectedRows > 0) {
                console.log('Subscription updated successfully for User ID:', userId);
            } else {
                console.error('No rows updated. Invalid User ID:', userId);
            }

        } catch (err) {
            console.error('Error updating database or retrieving subscription:', err.message);
        }
    } else {
        console.log(`Unhandled event type: ${event.type}`);
    }

    res.status(200).json({ received: true });
}

module.exports = { handleWebhook };
