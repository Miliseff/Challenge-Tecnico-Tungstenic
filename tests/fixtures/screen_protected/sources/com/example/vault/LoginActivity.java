package com.example.vault;

import android.app.Activity;
import android.os.Bundle;

public class LoginActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().addFlags(8192);
        setContentView(R.layout.activity_login);
    }
}
