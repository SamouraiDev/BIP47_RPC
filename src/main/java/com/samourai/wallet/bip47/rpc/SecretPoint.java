package com.samourai.wallet.bip47.rpc;

import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.spec.ECParameterSpec;
import org.spongycastle.jce.spec.ECPrivateKeySpec;
import org.spongycastle.jce.spec.ECPublicKeySpec;

import org.spongycastle.util.encoders.Hex;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

// https://www.reddit.com/r/Bitcoin/comments/3alzga/bip47_reusable_payment_codes/
// https://github.com/bitcoin/bips/blob/master/bip-0047.mediawiki

public class SecretPoint {

    private PrivateKey privKey = null;
    private PublicKey pubKey = null;

    private KeyFactory kf = null;

    private static final ECParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");

    static {
        Security.addProvider(new org.spongycastle.jce.provider.BouncyCastleProvider());
    }

    public SecretPoint()    { ; }

    public SecretPoint(byte[] dataPrv, byte[] dataPub) throws InvalidKeySpecException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, NoSuchProviderException {
        kf = KeyFactory.getInstance("ECDH", "SC");
        privKey = loadPrivateKey(dataPrv);
        pubKey = loadPublicKey(dataPub);
    }

    public PrivateKey getPrivKey() {
        return privKey;
    }

    public void setPrivKey(PrivateKey privKey) {
        this.privKey = privKey;
    }

    public PublicKey getPubKey() {
        return pubKey;
    }

    public void setPubKey(PublicKey pubKey) {
        this.pubKey = pubKey;
    }

    public byte[] ECDHSecretAsBytes() throws InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, NoSuchProviderException    {
        return ECDHSecret().getEncoded();
    }

    public boolean isShared(SecretPoint secret) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        return equals(secret);
    }

    private SecretKey ECDHSecret() throws InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, NoSuchProviderException    {

        KeyAgreement ka = KeyAgreement.getInstance("ECDH", "SC");
        ka.init(privKey);
        ka.doPhase(pubKey, true);
        SecretKey secret = ka.generateSecret("AES");

        return secret;
    }

    private boolean equals(SecretPoint secret) throws InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, NoSuchProviderException {
        return Hex.toHexString(this.ECDHSecretAsBytes()).equals(Hex.toHexString(secret.ECDHSecretAsBytes()));
    }

    private PublicKey loadPublicKey(byte[] data) throws InvalidKeySpecException    {
        ECPublicKeySpec pubKey = new ECPublicKeySpec(params.getCurve().decodePoint(data), params);
        return kf.generatePublic(pubKey);
    }

    private PrivateKey loadPrivateKey(byte[] data) throws InvalidKeySpecException  {
        ECPrivateKeySpec prvkey = new ECPrivateKeySpec(new BigInteger(1, data), params);
        return kf.generatePrivate(prvkey);
    }

}
