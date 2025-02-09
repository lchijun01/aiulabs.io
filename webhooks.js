const stripe = require('stripe')(process.env.STRIPE_API_KEY);
const mysql = require('mysql2/promise');

// ✅ Database connection
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});

async function handleWebhook(req, res) {
    console.log('📌 [WEBHOOK] Received a webhook request...');
    const sig = req.headers['stripe-signature'];
    let event;

    try {
        const rawBody = req.body.toString(); // Convert Buffer to string
        event = stripe.webhooks.constructEvent(rawBody, sig, process.env.STRIPE_WEBHOOK_SECRET);

        console.log('✅ [WEBHOOK] Stripe Event Type:', event.type);
    } catch (err) {
        console.error('❌ [WEBHOOK] Signature verification failed:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === 'checkout.session.completed') {
        console.log('📌 [WEBHOOK] Handling checkout.session.completed event');

        const session = event.data.object;
        console.log('🎯 [WEBHOOK] Session Data:', JSON.stringify(session, null, 2));

        const customerId = session.customer;
        const subscriptionId = session.subscription || null;
        const userId = session.metadata ? session.metadata.user_id : null;

        console.log(`📌 [WEBHOOK] Extracted user_id: ${userId}, stripe_customer_id: ${customerId}`);

        if (!customerId || !userId) {
            console.error('❌ [WEBHOOK] Missing customerId or userId:', { customerId, userId });
            return res.status(400).send('Missing required details.');
        }

        try {
            let endDate;
            if (subscriptionId) {
                console.log(`📌 [WEBHOOK] Retrieving subscription details for ${subscriptionId}`);
                const subscription = await stripe.subscriptions.retrieve(subscriptionId);
                endDate = new Date(subscription.current_period_end * 1000);
            } else {
                console.log('📌 [WEBHOOK] No subscription ID found. Defaulting to +30 days.');
                endDate = new Date();
                endDate.setDate(endDate.getDate() + 30);
            }

            const formattedEndDate = endDate.toISOString().slice(0, 19).replace("T", " ");
            console.log(`📌 [WEBHOOK] Calculated Subscription End Date: ${formattedEndDate}`);

            // ✅ Debug: Check if user exists before updating
            const [existingUser] = await db.query(`SELECT id FROM users WHERE id = ?`, [userId]);
            if (existingUser.length === 0) {
                console.error(`❌ [WEBHOOK] User ID ${userId} not found in database.`);
                return res.status(400).send('User not found.');
            }

            const updateQuery = `
                UPDATE users
                SET stripe_customer_id = ?, subscription_status = 'active', 
                    subscription_end_date = ?
                WHERE id = ?
            `;

            console.log(`🔄 [WEBHOOK] Updating DB for user_id: ${userId} with stripe_customer_id: ${customerId}`);

            // ✅ Fix TypeError issue by correctly handling MySQL response
            const result = await db.query(updateQuery, [customerId, formattedEndDate, userId]);
            console.log(`📌 [WEBHOOK] Raw MySQL Result:`, result);

            if (result[0].affectedRows > 0) {
                console.log(`✅ [WEBHOOK] Subscription updated successfully for User ID: ${userId}`);
            } else {
                console.error(`❌ [WEBHOOK] No rows updated. Possibly invalid User ID: ${userId}`);
            }

        } catch (err) {
            console.error('❌ [WEBHOOK] Error updating database:', err.message);
        }
    } else {
        console.log(`ℹ️ [WEBHOOK] Unhandled event type: ${event.type}`);
    }

    res.status(200).json({ received: true });
}

module.exports = { handleWebhook };
