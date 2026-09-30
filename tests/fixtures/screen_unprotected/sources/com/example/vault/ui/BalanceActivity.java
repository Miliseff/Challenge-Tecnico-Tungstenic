package com.example.vault.ui;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

public class BalanceActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_balance);
        ((TextView) findViewById(R.id.balance)).setText("Saldo disponible");
    }
}
