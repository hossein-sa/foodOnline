# Generated by Django 5.1.1 on 2024-10-10 12:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vendor', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='vendor',
            name='vendor_license',
            field=models.ImageField(max_length=255, upload_to='vendor/license'),
        ),
    ]
