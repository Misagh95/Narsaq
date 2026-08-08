package dev.narsaq.speedtester.ui

import android.os.Looper
import dev.narsaq.speedtester.MainActivity
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class MainActivityLaunchTest {

    @Test
    fun `main activity launches without crashing`() {
        val controller = Robolectric.buildActivity(MainActivity::class.java)
        val activity = controller.setup().get()
        assertNotNull(activity)
        shadowOf(Looper.getMainLooper()).idle()
        assertTrue("activity is finishing after crash", !activity.isFinishing)
    }
}
