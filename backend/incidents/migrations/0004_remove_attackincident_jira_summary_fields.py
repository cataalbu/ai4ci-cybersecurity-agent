from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("incidents", "0003_attackincident_jira_summary_fields"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="attackincident",
            name="jira_summary_title",
        ),
        migrations.RemoveField(
            model_name="attackincident",
            name="jira_description",
        ),
    ]
