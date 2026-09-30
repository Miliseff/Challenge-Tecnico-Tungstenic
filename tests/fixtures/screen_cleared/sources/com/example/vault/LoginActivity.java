package com.example.vault;

import android.app.Activity;
import android.os.Bundle;
import android.view.WindowManager;

public class LoginActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        setContentView(R.layout.activity_login);
    }

    public void onDebugToggle() {
        getWindow().clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
    }
}
