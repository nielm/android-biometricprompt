package com.example.kieun.biometricprompt;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.Handler;
import android.os.Looper;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.ActionBarDrawerToggle;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.view.GravityCompat;
import androidx.drawerlayout.widget.DrawerLayout;

import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.google.android.material.navigation.NavigationView;
import com.google.android.material.snackbar.Snackbar;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.util.UUID;
import java.util.concurrent.Executor;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class MainActivity extends AppCompatActivity
        implements NavigationView.OnNavigationItemSelectedListener {
    private static final String TAG = MainActivity.class.getName();

    private String mToBeSignedMessage;

    // Unique identifier of a key pair
    private static final String KEY_NAME = UUID.randomUUID().toString();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        FloatingActionButton fab = findViewById(R.id.fab);
        fab.setOnClickListener(new View.OnClickListener() {
            @SuppressLint("WrongConstant")
            @Override
            public void onClick(View view) {
                Snackbar.make(view, "Replace with your own action", Snackbar.LENGTH_LONG)
                        .setAction("Action", null).show();
            }
        });

        DrawerLayout drawer = findViewById(R.id.drawer_layout);
        ActionBarDrawerToggle toggle = new ActionBarDrawerToggle(
                this, drawer, toolbar, R.string.navigation_drawer_open, R.string.navigation_drawer_close);
        drawer.addDrawerListener(toggle);
        toggle.syncState();

        NavigationView navigationView = findViewById(R.id.nav_view);
        navigationView.setNavigationItemSelectedListener(this);

        iniKey();
    }

    private void iniKey() {
        try {
            final KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,
                    "AndroidKeyStore");
            keyGenerator.init(new
                    KeyGenParameterSpec.Builder(KEY_NAME + "Fingerprint",
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(
                            KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());
            keyGenerator.generateKey();
        } catch (Exception e){
            throw new RuntimeException(e);
        }
    }

    @Override
    public void onBackPressed() {
        DrawerLayout drawer = findViewById(R.id.drawer_layout);
        if (drawer.isDrawerOpen(GravityCompat.START)) {
            drawer.closeDrawer(GravityCompat.START);
        } else {
            super.onBackPressed();
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    @Override
    public boolean onNavigationItemSelected(MenuItem item) {
        // Handle navigation view item clicks here.
        int id = item.getItemId();

        if (id == R.id.nav_register) {
            if (canAuthenticateWithStrongBiometrics()) {  // Check whether this device can authenticate with biometrics
                Log.i(TAG, "Try registration");
                // Generate keypair and init signature
                Signature signature;
                try {
                    KeyPair keyPair = generateKeyPair(KEY_NAME, true);
                    // Send public key part of key pair to the server, this public key will be used for authentication
                    mToBeSignedMessage = Base64.encodeToString(keyPair.getPublic().getEncoded(), Base64.URL_SAFE) +
                            ":" +
                            KEY_NAME +
                            ":" +
                            // Generated by the server to protect against replay attack
                            "12345";

                    signature = initSignature(KEY_NAME);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }

                // Create biometricPrompt
                showBiometricPrompt(signature);
            } else {
                // Cannot use biometric prompt
                Toast.makeText(this, "Cannot use biometric", Toast.LENGTH_SHORT).show();
            }
        } else if (id == R.id.nav_authenticate) {
            if (canAuthenticateWithStrongBiometrics()) {  // Check whether this device can authenticate with biometrics
                Log.i(TAG, "Try authentication");

                // Init signature
                Signature signature;
                try {
                    // Send key name and challenge to the server, this message will be verified with registered public key on the server
                    mToBeSignedMessage = KEY_NAME +
                            ":" +
                            // Generated by the server to protect against replay attack
                            "12345";
                    signature = initSignature(KEY_NAME);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }

                if(signature == null) {
                    Toast.makeText(this, "Key not yet registered", Toast.LENGTH_SHORT).show();
                } else {
                    // Create biometricPrompt
                    showBiometricPrompt(signature);
                }
            } else {
                // Cannot use biometric prompt
                Toast.makeText(this, "Cannot use biometric", Toast.LENGTH_SHORT).show();
            }
        }  else if (id == R.id.nav_fingerprint) {
            showFingerprintPrompt();
        }


        DrawerLayout drawer = findViewById(R.id.drawer_layout);
        drawer.closeDrawer(GravityCompat.START);
        return true;
    }

    private Cipher getCryptoObject() throws Exception{
        final Cipher cipher = Cipher.getInstance(
                KeyProperties.KEY_ALGORITHM_AES + "/"
                        + KeyProperties.BLOCK_MODE_CBC + "/"
                        + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        ;
        final KeyStore keyStore =  KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        final SecretKey key = (SecretKey) keyStore.getKey(KEY_NAME + "Fingerprint", null);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher;
    }
    private void showFingerprintPrompt()  {
        try {
            FingerprintManager fingerprintManager = (FingerprintManager)
                    getApplicationContext().getSystemService(Context.FINGERPRINT_SERVICE);

            CancellationSignal cancellationSignal = new CancellationSignal();

            if (fingerprintManager.isHardwareDetected() && fingerprintManager.hasEnrolledFingerprints()) {
                fingerprintManager.authenticate(new FingerprintManager.CryptoObject(getCryptoObject()),
                        cancellationSignal, 0, new FingerprintManager.AuthenticationCallback() {
                            @Override
                            public void onAuthenticationError(int errorCode, CharSequence errString) {
                                super.onAuthenticationError(errorCode, errString);
                                Toast.makeText(getApplicationContext(), "Fingerprint.onAuthenticationError", Toast.LENGTH_SHORT).show();

                            }

                            @Override
                            public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                                super.onAuthenticationHelp(helpCode, helpString);
                                Toast.makeText(getApplicationContext(), "Fingerprint.onAuthenticationHelp", Toast.LENGTH_SHORT).show();

                            }

                            @Override
                            public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                                super.onAuthenticationSucceeded(result);
                                Toast.makeText(getApplicationContext(), "Fingerprint.onAuthenticationSucceeded", Toast.LENGTH_SHORT).show();

                            }

                            @Override
                            public void onAuthenticationFailed() {
                                super.onAuthenticationFailed();
                                Toast.makeText(getApplicationContext(), "Fingerprint.onAuthenticationFailed", Toast.LENGTH_SHORT).show();

                            }
                        }, null);

            } else {
                Toast.makeText(getApplicationContext(), "fingerprint not supported", Toast.LENGTH_SHORT).show();

            }
        } catch (Exception e){
            throw new RuntimeException(e);
        }
    }


    private void showBiometricPrompt(Signature signature) {
        BiometricPrompt.AuthenticationCallback authenticationCallback = getAuthenticationCallback();
        BiometricPrompt mBiometricPrompt = new BiometricPrompt(this, getMainThreadExecutor(), authenticationCallback);

        // Set prompt info
        BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
                .setDescription("Description")
                .setTitle("Title")
                .setSubtitle("Subtitle")
                .setNegativeButtonText("Cancel")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build();

        // Show biometric prompt
        if (signature != null) {
            Log.i(TAG, "Show biometric prompt");
            mBiometricPrompt.authenticate(promptInfo, new BiometricPrompt.CryptoObject(signature));
        }
    }

    private BiometricPrompt.AuthenticationCallback getAuthenticationCallback() {
        // Callback for biometric authentication result
        return new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                Log.e(TAG, "Error code: " + errorCode + "error String: " + errString);
                super.onAuthenticationError(errorCode, errString);
            }

            @Override
            public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                Log.i(TAG, "onAuthenticationSucceeded");
                Log.i(TAG, "result.authenticationType: " + result.getAuthenticationType());

                super.onAuthenticationSucceeded(result);
                if (result.getCryptoObject() != null &&
                        result.getCryptoObject().getSignature() != null) {
                    try {
                        Signature signature = result.getCryptoObject().getSignature();
                        signature.update(mToBeSignedMessage.getBytes());
                        String signatureString = Base64.encodeToString(signature.sign(), Base64.URL_SAFE);
                        // Normally, ToBeSignedMessage and Signature are sent to the server and then verified
                        Log.i(TAG, "Message: " + mToBeSignedMessage);
                        Log.i(TAG, "Signature (Base64 Encoded): " + signatureString);
                        Toast.makeText(getApplicationContext(), "Signed successfully.", Toast.LENGTH_LONG).show();
                    } catch (SignatureException e) {
                        Log.e(TAG,"signature failed",e);
                        throw new RuntimeException(e);
                    }
                } else {
                    // Error
                    Toast.makeText(getApplicationContext(), "Something wrong", Toast.LENGTH_SHORT).show();
                }
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
            }
        };
    }

    private KeyPair generateKeyPair(String keyName, boolean invalidatedByBiometricEnrollment) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");

        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(keyName,
                KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256,
                        KeyProperties.DIGEST_SHA384,
                        KeyProperties.DIGEST_SHA512)
                // Require the user to authenticate with a biometric to authorize every use of the key
                .setUserAuthenticationRequired(true);

        // Generated keys will be invalidated if the biometric templates are added more to user device
        if (Build.VERSION.SDK_INT >= 24) {
            builder.setInvalidatedByBiometricEnrollment(invalidatedByBiometricEnrollment);
        }

        keyPairGenerator.initialize(builder.build());

        return keyPairGenerator.generateKeyPair();
    }

    @Nullable
    private KeyPair getKeyPair(String keyName) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (keyStore.containsAlias(keyName)) {
            // Get public key
            PublicKey publicKey = keyStore.getCertificate(keyName).getPublicKey();
            // Get private key
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyName, null);
            // Return a key pair
            return new KeyPair(publicKey, privateKey);
        }
        return null;
    }

    @Nullable
    private Signature initSignature (String keyName) throws Exception {
        KeyPair keyPair = getKeyPair(keyName);

        if (keyPair != null) {
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(keyPair.getPrivate());
            return signature;
        }
        return null;
    }

    private Executor getMainThreadExecutor() {
        return new MainThreadExecutor();
    }

    private static class MainThreadExecutor implements Executor {
        private final Handler handler = new Handler(Looper.getMainLooper());

        @Override
        public void execute(@NonNull Runnable r) {
            handler.post(r);
        }
    }

    /**
     * Indicate whether this device can authenticate the user with strong biometrics
     * @return true if there are any available strong biometric sensors and biometrics are enrolled on the device, if not, return false
     */
    private boolean canAuthenticateWithStrongBiometrics() {
        return BiometricManager.from(this).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS;
    }
}
