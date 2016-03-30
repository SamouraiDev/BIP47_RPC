package com.samourai.wallet.bip47.rpc;

import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.core.ECKey;

import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.ec.CustomNamedCurves;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import com.samourai.wallet.bip47.rpc.NotSecp256k1Exception;

public class PaymentAddress {

    private PaymentCode paymentCode = null;
    private int index = 0;
    private byte[] privKey = null;

    private static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");
    private static final ECDomainParameters CURVE = new ECDomainParameters(CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(), CURVE_PARAMS.getH());

    public PaymentAddress()    {
        paymentCode = null;
        privKey = null;
        index = 0;
    }

    public PaymentAddress(PaymentCode paymentCode) throws AddressFormatException {
        this.paymentCode = paymentCode;
        this.index = 0;
        this.privKey = null;
    }

    public PaymentAddress(PaymentCode paymentCode, int index, byte[] privKey) throws AddressFormatException {
        this.paymentCode = paymentCode;
        this.index = index;
        this.privKey = privKey;
    }

    public PaymentCode getPaymentCode() {
        return paymentCode;
    }

    public void setPaymentCode(PaymentCode paymentCode) {
        this.paymentCode = paymentCode;
    }

    public int getIndex() {
        return index;
    }

    public void setIndex(int index) {
        this.index = index;
    }

    public byte[] getPrivKey() {
        return privKey;
    }

    public void setIndexAndPrivKey(int index, byte[] privKey) {
        this.index = index;
        this.privKey = privKey;
    }

    public void setPrivKey(byte[] privKey) {
        this.privKey = privKey;
    }

    public ECKey getSendECKey() throws AddressFormatException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, InvalidKeySpecException, NotSecp256k1Exception {
        return getSendECKey(getSecretPoint());
    }

    public ECKey getReceiveECKey() throws AddressFormatException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, InvalidKeySpecException, NotSecp256k1Exception {
        return getReceiveECKey(getSecretPoint());
    }

    public ECPoint get_sG() throws AddressFormatException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, InvalidKeySpecException, NotSecp256k1Exception    {
        return CURVE_PARAMS.getG().multiply(getSecretPoint());
    }

    public SecretPoint getSharedSecret() throws AddressFormatException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, InvalidKeySpecException   {
        return sharedSecret();
    }

    public BigInteger getSecretPoint() throws AddressFormatException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, InvalidKeySpecException, NotSecp256k1Exception    {
        return secretPoint();
    }

    public ECPoint getECPoint() throws AddressFormatException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, InvalidKeySpecException    {
        ECKey ecKey = ECKey.fromPublicOnly(paymentCode.addressAt(index).getPubKey());
        return ecKey.getPubKeyPoint();
    }

    public byte[] hashSharedSecret() throws AddressFormatException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, InvalidKeySpecException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(getSharedSecret().ECDHSecretAsBytes());
        return hash;
    }

    private ECPoint get_sG(BigInteger s) {
        return CURVE_PARAMS.getG().multiply(s);
    }

    private ECKey getSendECKey(BigInteger s) throws AddressFormatException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, InvalidKeySpecException{
        ECPoint ecPoint = getECPoint();
        ECPoint sG = get_sG(s);
        ECKey ecKey = ECKey.fromPublicOnly(ecPoint.add(sG).getEncoded(true));
        return ecKey;
    }

    private ECKey getReceiveECKey(BigInteger s)  {
        BigInteger privKeyValue = ECKey.fromPrivate(privKey).getPrivKey();
        ECKey ecKey = ECKey.fromPrivate(addSecp256k1(privKeyValue, s));
        return ecKey;
    }

    private BigInteger addSecp256k1(BigInteger b1, BigInteger b2) {

        BigInteger ret = b1.add(b2);

        if(ret.bitLength() > CURVE.getN().bitLength()) {
            return ret.mod(CURVE.getN());
        }

        return ret;
    }

    private SecretPoint sharedSecret() throws AddressFormatException, InvalidKeySpecException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, NoSuchProviderException {
        return new SecretPoint(privKey, paymentCode.addressAt(index).getPubKey());
    }

    private boolean isSecp256k1(BigInteger b) {

        if(b.compareTo(BigInteger.ONE) <= 0 || b.bitLength() > CURVE.getN().bitLength()) {
            return false;
        }

        return true;
    }

    private BigInteger secretPoint() throws AddressFormatException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, NotSecp256k1Exception  {
        //
        // convert hash to value 's'
        //
        BigInteger s = new BigInteger(1, hashSharedSecret());
        //
        // check that 's' is on the secp256k1 curve
        //
        if(!isSecp256k1(s))    {
            throw new NotSecp256k1Exception("secret point not on Secp256k1 curve");
        }

        return s;
    }

}
