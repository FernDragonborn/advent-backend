# Generated by Django 5.1.3 on 2024-12-07 09:20

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("advent_app", "0011_remove_task_created_at_taskresponse_created_at"),
    ]

    operations = [
        migrations.AlterField(
            model_name="taskresponse",
            name="created_at",
            field=models.DateTimeField(auto_now_add=True),
        ),
    ]
