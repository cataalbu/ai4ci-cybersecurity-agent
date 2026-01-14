from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("incidents", "0002_attackincident_jira_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="attackincident",
            name="jira_summary_title",
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name="attackincident",
            name="jira_description",
            field=models.TextField(blank=True, null=True),
        ),
    ]
