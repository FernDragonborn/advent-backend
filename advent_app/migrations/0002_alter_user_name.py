# Generated by Django 5.1.3 on 2024-11-27 16:58

import advent_app.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('advent_app', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='name',
            field=models.CharField(max_length=150, validators=[advent_app.models.validate_name]),
        ),
    ]
