package com.d.phishsafe;

import android.net.Uri;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.Toast;

import com.google.android.gms.common.api.ApiException;
import com.google.android.gms.common.api.CommonStatusCodes;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.safetynet.SafetyNet;
import com.google.android.gms.safetynet.SafetyNetApi;
import com.google.android.gms.tasks.OnFailureListener;
import com.google.android.gms.tasks.OnSuccessListener;
import com.google.android.gms.tasks.Tasks;

import java.util.concurrent.ExecutionException;

public class MainActivity extends AppCompatActivity {

    String TAG = "##############################";
    GoogleApiClient mGoogleApiClient;

    EditText url ;
    Button test ;

    String uri;
    ImageView im;

    @Override
    protected void onResume() {
        super.onResume();
        new Thread(new Runnable() {
            @Override
            public void run() {

                try {
                    Tasks.await(SafetyNet.getClient(MainActivity.this).initSafeBrowsing());
                } catch (ExecutionException e) {
                    e.printStackTrace();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }).start();


    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        im = findViewById(R.id.img);

        url = findViewById(R.id.url);
        test = findViewById(R.id.test);
        Uri data = this.getIntent().getData();
        if (data != null && data.isHierarchical()) {
            uri = this.getIntent().getDataString();
            Log.i("MyApp", "Deep link clicked " + uri);

        }

        url.setText(uri);
        test.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                if(!url.getText().toString().isEmpty()) {
                    String link = url.getText().toString();

                    test(link);
                }

                else
                    {
                        Toast.makeText(MainActivity.this, "Enter URL!!!", Toast.LENGTH_SHORT).show();
                    }


            }
        });




}

public void test(String url)
{

    SafetyNet.getClient(this).lookupUri(url,
            "AIzaSyBSVUeMUxzGxxUnR3GtztAnG1zTLZ-kCLU",
            SafeBrowsingThreat.TYPE_POTENTIALLY_HARMFUL_APPLICATION,
            SafeBrowsingThreat.TYPE_SOCIAL_ENGINEERING)
            .addOnSuccessListener(this,
                    new OnSuccessListener<SafetyNetApi.SafeBrowsingResponse>() {
                        @Override
                        public void onSuccess(SafetyNetApi.SafeBrowsingResponse sbResponse) {
                            // Indicates communication with the service was successful.
                            // Identify any detected threats.
                            if (sbResponse.getDetectedThreats().isEmpty()) {
                                // No threats found.
                                im.setImageResource(R.drawable.check_circle);
                                Toast.makeText(MainActivity.this, "No threats found.", Toast.LENGTH_LONG).show();
                            } else {
                                // Threats found!
                                im.setImageResource(R.drawable.close_circle);
                                Toast.makeText(MainActivity.this, "Threats found!", Toast.LENGTH_LONG).show();
                            }
                        }
                    })
            .addOnFailureListener(this, new OnFailureListener() {
                @Override
                public void onFailure(@NonNull Exception e) {
                    // An error occurred while communicating with the service.
                    if (e instanceof ApiException) {
                        // An error with the Google Play Services API contains some
                        // additional details.
                        ApiException apiException = (ApiException) e;
                        Log.d(TAG, "Error: " + CommonStatusCodes
                                .getStatusCodeString(apiException.getStatusCode()));

                        // Note: If the status code, apiException.getStatusCode(),
                        // is SafetyNetstatusCode.SAFE_BROWSING_API_NOT_INITIALIZED,
                        // you need to call initSafeBrowsing(). It means either you
                        // haven't called initSafeBrowsing() before or that it needs
                        // to be called again due to an internal error.
                    } else {
                        // A different, unknown type of error occurred.
                        Log.d(TAG, "Error: " + e.getMessage());
                    }
                }
            });
}

}

class SafeBrowsingThreat {

    /**
     * This threat type identifies URLs of pages that are flagged as containing potentially
     * harmful applications.
     */
    public static final int TYPE_POTENTIALLY_HARMFUL_APPLICATION = 4;

    /**
     * This threat type identifies URLs of pages that are flagged as containing social
     * engineering threats.
     */
    public static final int TYPE_SOCIAL_ENGINEERING = 5;
}
