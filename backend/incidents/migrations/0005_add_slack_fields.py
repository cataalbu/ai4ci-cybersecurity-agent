from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("incidents", "0004_remove_attackincident_jira_summary_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="attackincident",
            name="slack_notified_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="attackincident",
            name="last_slack_error",
            field=models.TextField(blank=True, null=True),
        ),
    ]
