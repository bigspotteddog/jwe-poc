# Auth0 JWT Configuration Guide

## Issue Summary
Your Auth0 application is currently configured to return **JWE tokens** (encrypted) instead of **JWT tokens** (signed only). While our application can detect and attempt to decrypt JWE tokens, we need the correct shared secret key from Auth0 for successful decryption.

**Current Status:**
- ✅ JWE token detection working (5-part tokens)
- ✅ Key length processing fixed (256-bit keys)
- ⚠️ Decryption fails due to incorrect shared secret ("Tag mismatch" error)

## Recommended Solution: Configure Auth0 for JWT Tokens

### Step 1: Access Auth0 Dashboard
1. Go to [Auth0 Dashboard](https://manage.auth0.com/)
2. Navigate to **Applications** → **Applications**
3. Find your application: `sonatype-mtiq-test`

### Step 2: Application Settings
1. Click on your application name
2. Go to the **Settings** tab
3. Scroll to **Application URIs** section

### Step 3: Token Configuration
1. Scroll down to **Advanced Settings**
2. Click **Advanced Settings** to expand
3. Go to the **OAuth** tab

### Step 4: Disable JWE Encryption
Look for these settings and configure as follows:

**JsonWebToken Signature Algorithm:**
- Set to: `RS256` (NOT `RS256` + encryption)
- Avoid: `RSA-OAEP-256`, `A256GCM`, or other encrypted variants

**ID Token Encryption:**
- Set to: `None` or `Disabled`
- If present, uncheck encryption options

**Access Token Format:**
- Set to: `JWT` (not `Opaque`)

### Step 5: Application Type Verification
Ensure your application is configured as:
- **Application Type**: `Single Page Application` (SPA)
- **Token Endpoint Authentication Method**: `None`

### Step 6: Save and Test
1. Click **Save Changes**
2. Test the application - tokens should now be 3-part JWT tokens instead of 5-part JWE tokens

## Alternative: Find Auth0 Shared Secret

If you need to keep JWE tokens, locate the shared secret:

### Option A: Application Settings
1. In Auth0 Dashboard → **Applications** → **[Your App]**
2. Look for **Client Secret** (this might be used for JWE)
3. Check if there's a specific **JWE Encryption Key** setting

### Option B: APIs Configuration
1. Go to **Applications** → **APIs**
2. Check if there's a custom API configured
3. Look for encryption settings in the API configuration

### Option C: Tenant Settings
1. Go to **Settings** → **Advanced**
2. Look for global encryption settings

## Testing Your Configuration

### Test 1: Check Token Format
After making changes, use the browser's developer tools:
1. Login to your application
2. Check the Network tab for Auth0 requests
3. Look at the token in the response - it should have 3 parts (JWT) instead of 5 parts (JWE)

### Test 2: Use Our Debug Endpoints
```bash
# Check current JWE status
curl -k https://localhost:8443/jwe/status

# Test key configurations
curl -k https://localhost:8443/jwe/key-test
```

### Test 3: Monitor Application Logs
Look for this log entry:
- ✅ Good: `Processing JWT token (3 parts)`
- ⚠️ Still encrypted: `Processing JWE token (5 parts)`

## Expected Results

After successful configuration:
1. **Login Flow**: Should work normally
2. **Token Format**: 3-part JWT tokens instead of 5-part JWE
3. **API Token Creation**: Should work without decryption errors
4. **Application Logs**: Should show "Processing JWT token (3 parts)"

## If You Must Keep JWE Tokens

If JWE tokens are required for your setup:

1. **Find the correct shared secret** from Auth0 configuration
2. **Update application.properties**:
   ```properties
   jwe.shared-secret=YOUR_ACTUAL_AUTH0_SECRET_HERE
   jwe.enabled=true
   ```
3. **Restart the application**
4. **Test API token creation**

## Support

If you need help finding specific Auth0 settings:
1. Check Auth0 documentation for your specific tenant type
2. Contact Auth0 support with your tenant details
3. Use Auth0 Management API to inspect current configuration

The key insight is that JWE decryption requires the **exact same 256-bit secret** that Auth0 used for encryption, and this is typically not exposed in the standard Auth0 configuration interface.