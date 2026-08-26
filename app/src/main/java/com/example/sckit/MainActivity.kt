package com.example.sckit

import android.app.Activity
import android.content.ContentResolver
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material.Button
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Surface
import androidx.compose.material.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.platform.LocalContext
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    DecoderScreen()
                }
            }
        }
    }
}

@Composable
fun DecoderScreen() {
    val context = LocalContext.current
    var input by remember { mutableStateOf("") }
    var selectedFile by remember { mutableStateOf<String?>(null) }
    var results by remember { mutableStateOf(listOf<String>()) }

    val filePickerLauncher = (context as Activity).registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        uri?.let {
            selectedFile = uri.lastPathSegment ?: uri.toString()
            // For demo, copy asset / show toast
            Toast.makeText(context, "Selected: $selectedFile", Toast.LENGTH_SHORT).show()
        }
    }

    Column(modifier = Modifier.padding(16.dp)) {
        Text("SckitDecoder", style = MaterialTheme.typography.h5)
        Spacer(Modifier.height(12.dp))
        Text("Paste a string to decode:")
        BasicTextField(value = input, onValueChange = { input = it }, modifier = Modifier
            .fillMaxWidth()
            .height(120.dp))
        Spacer(Modifier.height(8.dp))
        Row {
            Button(onClick = { filePickerLauncher.launch(arrayOf("*/*")) }) {
                Text("Pick file")
            }
            Spacer(Modifier.width(8.dp))
            Button(onClick = {
                // copy the bundled Python asset to app files directory so user may invoke it via Termux/Chaquopy later
                val copied = copyAssetToFiles(context.contentResolver, "sckit.py", context.filesDir.absolutePath)
                if (copied)
                    Toast.makeText(context, "Python asset copied to files/ (ready)", Toast.LENGTH_SHORT).show()
                else
                    Toast.makeText(context, "Failed to copy asset", Toast.LENGTH_SHORT).show()
            }) {
                Text("Install script")
            }
        }
        Spacer(Modifier.height(12.dp))
        Button(onClick = {
            // Placeholder: in an integrated build with Chaquopy you'd call Python here
            // For now we just simulate a result
            results = listOf("Decoded: example1", "Decoded: example2")
        }) {
            Text("Decode")
        }
        Spacer(Modifier.height(12.dp))
        Text("Results:")
        for (r in results) {
            Text("• $r")
        }
    }
}

fun copyAssetToFiles(resolver: ContentResolver, assetName: String, destDir: String): Boolean {
    try {
        val input: InputStream = resolver.openAssetFileDescriptor(Uri.parse("file:///android_asset/$assetName"), "r")!!.createInputStream()
        val outFile = File(destDir, assetName)
        FileOutputStream(outFile).use { out ->
            input.copyTo(out)
        }
        return true
    } catch (e: Exception) {
        e.printStackTrace()
        return false
    }
}
