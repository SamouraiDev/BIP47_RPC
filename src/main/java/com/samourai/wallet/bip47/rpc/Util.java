package com.samourai.wallet.bip47.rpc;

import org.bitcoinj.core.bip47.Wallet;
import org.bitcoinj.core.bip47.Address;
import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.core.DumpedPrivateKey;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.params.MainNetParams;

import java.io.IOException;

public class Util {

    private static Util instance = null;

    private Util() { ; }

    public static Util getInstance() {

        if(instance == null) {
            instance = new Util();
        }

        return instance;
    }

    public Address getNotificationAddress(Wallet wallet) {
        return wallet.getAccount(0).addressAt(0);
    }

    public PaymentCode getPaymentCode(Wallet wallet) throws AddressFormatException   {
        String payment_code = wallet.getAccount(0).getPaymentCode();
        return new PaymentCode(payment_code);
    }

    public PaymentAddress getReceiveAddress(Wallet wallet, PaymentCode pcode, int idx) throws AddressFormatException, NotSecp256k1Exception {
        Address address = wallet.getAccount(0).addressAt(idx);
        return getPaymentAddress(pcode, 0, address);
    }

    public PaymentAddress getSendAddress(Wallet wallet, PaymentCode pcode, int idx) throws AddressFormatException, NotSecp256k1Exception {
        Address address = wallet.getAccount(0).addressAt(0);
        return getPaymentAddress(pcode, idx, address);
    }

    public byte[] getIncomingMask(Wallet wallet, byte[] pubkey, byte[] outPoint) throws AddressFormatException, Exception    {

        Address notifAddress = getNotificationAddress(wallet);
        DumpedPrivateKey dpk = new DumpedPrivateKey(MainNetParams.get(), notifAddress.getPrivateKeyString());
        ECKey inputKey = dpk.getKey();
        byte[] privkey = inputKey.getPrivKeyBytes();
        byte[] mask = PaymentCode.getMask(new SecretPoint(privkey, pubkey).ECDHSecretAsBytes(), outPoint);

        return mask;
    }

    public PaymentAddress getPaymentAddress(PaymentCode pcode, int idx, Address address) throws AddressFormatException, NotSecp256k1Exception {
        DumpedPrivateKey dpk = new DumpedPrivateKey(MainNetParams.get(), address.getPrivateKeyString());
        ECKey eckey = dpk.getKey();
        PaymentAddress paymentAddress = new PaymentAddress(pcode, idx, eckey.getPrivKeyBytes());
        return paymentAddress;
    }

}
