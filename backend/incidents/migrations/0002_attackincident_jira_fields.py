from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("incidents", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="attackincident",
            name="jira_issue_key",
            field=models.CharField(blank=True, db_index=True, max_length=50, null=True),
        ),
        migrations.AddField(
            model_name="attackincident",
            name="jira_issue_url",
            field=models.URLField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="attackincident",
            name="jira_created_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="attackincident",
            name="last_jira_error",
            field=models.TextField(blank=True, null=True),
        ),
    ]
